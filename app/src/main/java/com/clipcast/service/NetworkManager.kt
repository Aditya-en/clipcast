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
                updateBroadcastAddress(network)
            }

            override fun onLost(network: Network) {
                currentBroadcastAddress = null
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
            connectivityManager.unregisterNetworkCallback(it)
            networkCallback = null
        }
        currentBroadcastAddress = null
    }

    fun getCurrentBroadcastAddress(): InetAddress? = currentBroadcastAddress

    private fun updateBroadcastAddress(network: Network) {
        val linkProperties = connectivityManager.getLinkProperties(network)
        val newAddress = computeBroadcastAddress(linkProperties)

        if (newAddress != currentBroadcastAddress) {
            currentBroadcastAddress = newAddress
            listener?.onBroadcastAddressChanged(newAddress)
        }
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