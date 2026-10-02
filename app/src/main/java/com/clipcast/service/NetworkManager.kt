package com.clipcast.service

import android.content.Context
import android.net.ConnectivityManager
import android.net.LinkAddress
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.util.Log
import java.net.Inet4Address
import java.net.InetAddress

class NetworkManager(private val context: Context) {
    private val connectivityManager = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    private var currentBroadcastAddress: InetAddress? = null
    private var currentLocalIpv4: String? = null
    private var wifiConnected = false
    private var listener: BroadcastAddressListener? = null

    interface BroadcastAddressListener {
        fun onBroadcastAddressChanged(address: InetAddress?)
    }

    fun setListener(listener: BroadcastAddressListener) {
        this.listener = listener
    }

    fun start() {
        val request = NetworkRequest.Builder()
            .addTransportType(NetworkCapabilities.TRANSPORT_WIFI)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .build()

        networkCallback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                updateBroadcastAddress(network, notifyAlways = true)
            }

            override fun onLost(network: Network) {
                currentBroadcastAddress = null
                currentLocalIpv4 = null
                wifiConnected = false
                listener?.onBroadcastAddressChanged(null)
            }

            override fun onCapabilitiesChanged(network: Network, networkCapabilities: NetworkCapabilities) {
                updateBroadcastAddress(network)
            }

            override fun onLinkPropertiesChanged(network: Network, linkProperties: LinkProperties) {
                updateBroadcastAddress(network)
            }
        }

        connectivityManager.registerNetworkCallback(request, networkCallback!!)
    }

    fun stop() {
        networkCallback?.let {
            try {
                connectivityManager.unregisterNetworkCallback(it)
            } catch (e: Exception) {
                // Already unregistered; ignore.
            }
            networkCallback = null
        }
        currentBroadcastAddress = null
        currentLocalIpv4 = null
        wifiConnected = false
    }

    fun getCurrentBroadcastAddress(): InetAddress? = currentBroadcastAddress

    /** Device's local IPv4 address (for the status line), or null. */
    fun getLocalIpv4(): String? = currentLocalIpv4

    /** True while the Wi-Fi network request is satisfied. */
    fun isWifiConnected(): Boolean = wifiConnected

    private fun updateBroadcastAddress(network: Network, notifyAlways: Boolean = false) {
        // Runs on the ConnectivityThread; never let it throw (would kill the process).
        // On any failure fall back to the limited broadcast address.
        val linkProperties = try {
            connectivityManager.getLinkProperties(network)
        } catch (e: Exception) {
            android.util.Log.w("ClipcastNet", "LinkProperties unavailable", e)
            null
        }
        val localIp = firstInet4Address(linkProperties)
        val newAddress = try {
            computeBroadcastAddress(linkProperties)
        } catch (e: Exception) {
            android.util.Log.w("ClipcastNet", "LinkProperties unavailable, using 255.255.255.255", e)
            try {
                InetAddress.getByName("255.255.255.255")
            } catch (e2: Exception) {
                null
            }
        }

        val changed = newAddress != currentBroadcastAddress || localIp != currentLocalIpv4
        wifiConnected = true
        currentLocalIpv4 = localIp
        if (newAddress != null) {
            currentBroadcastAddress = newAddress
        }
        if (changed || notifyAlways) {
            listener?.onBroadcastAddressChanged(currentBroadcastAddress)
        }
    }

    private fun firstInet4Address(linkProperties: LinkProperties?): String? {
        linkProperties?.linkAddresses?.forEach { linkAddress ->
            val address = linkAddress.address
            if (address is Inet4Address) {
                return address.hostAddress
            }
        }
        return null
    }

    private fun computeBroadcastAddress(linkProperties: LinkProperties?): InetAddress? {
        linkProperties?.linkAddresses?.forEach { linkAddress ->
            val address = linkAddress.address
            if (address is Inet4Address) {
                val prefixLength = linkAddress.prefixLength
                if (prefixLength >= 0 && prefixLength <= 32) {
                    return computeDirectedBroadcast(address, prefixLength)
                }
            }
        }

        return try {
            InetAddress.getByName("255.255.255.255")
        } catch (e: Exception) {
            null
        }
    }

    private fun computeDirectedBroadcast(address: Inet4Address, prefixLength: Int): InetAddress {
        val ipBytes = address.address
        val ipInt = bytesToInt(ipBytes)

        val mask: Int = if (prefixLength == 0) 0 else (-1 shl (32 - prefixLength))
        val networkInt = ipInt and mask
        val broadcastInt = networkInt or mask.inv()

        return try {
            InetAddress.getByAddress(intToBytes(broadcastInt))
        } catch (e: Exception) {
            InetAddress.getByName("255.255.255.255")
        }
    }

    private fun bytesToInt(bytes: ByteArray): Int {
        var result = 0
        for (i in 0..3) {
            result = (result shl 8) + (bytes[i].toInt() and 0xFF)
        }
        return result
    }

    private fun intToBytes(value: Int): ByteArray {
        return ByteArray(4).apply {
            this[0] = (value ushr 24).toByte()
            this[1] = (value ushr 16).toByte()
            this[2] = (value ushr 8).toByte()
            this[3] = (value and 0xFF).toByte()
        }
    }
}