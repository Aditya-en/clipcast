package com.clipcast.protocol

import java.util.Arrays

class SyncState {
    private var lamport: Long = 0
    private var lastAppliedLamport: Long = 0
    private var lastAppliedDeviceId: ByteArray = ByteArray(16)

    fun getLamport(): Long = lamport

    fun getLastApplied(): Pair<Long, ByteArray> = Pair(lastAppliedLamport, lastAppliedDeviceId.copyOf())

    fun onLocalSend(nowMs: Long, ourDeviceId: ByteArray): Long {
        lamport = maxOf(lamport, nowMs) + 1
        lastAppliedLamport = lamport
        lastAppliedDeviceId = ourDeviceId.copyOf()
        return lamport
    }

    @Deprecated("Use onLocalSend(nowMs, ourDeviceId)", ReplaceWith("onLocalSend(nowMs, ByteArray(16))"))
    fun onLocalSend(nowMs: Long): Long {
        lamport = maxOf(lamport, nowMs) + 1
        lastAppliedLamport = lamport
        return lamport
    }

    fun onReceive(remoteLamport: Long, remoteDeviceId: ByteArray): Boolean {
        if (Arrays.equals(remoteDeviceId, lastAppliedDeviceId) && remoteLamport == lastAppliedLamport) {
            return false
        }

        val shouldApply = compareTuples(remoteLamport, remoteDeviceId, lastAppliedLamport, lastAppliedDeviceId) > 0

        if (shouldApply) {
            lamport = maxOf(lamport, remoteLamport)
            lastAppliedLamport = remoteLamport
            lastAppliedDeviceId = remoteDeviceId.copyOf()
        }

        return shouldApply
    }

    fun updateLastApplied(lamport: Long, deviceId: ByteArray) {
        lastAppliedLamport = lamport
        lastAppliedDeviceId = deviceId.copyOf()
    }

    private fun compareTuples(
        lamport1: Long, deviceId1: ByteArray,
        lamport2: Long, deviceId2: ByteArray
    ): Int {
        if (lamport1 != lamport2) {
            return if (lamport1 < lamport2) -1 else 1
        }
        return compareDeviceIds(deviceId1, deviceId2)
    }

    private fun compareDeviceIds(id1: ByteArray, id2: ByteArray): Int {
        for (i in 0 until 16) {
            val b1 = id1[i].toInt() and 0xFF
            val b2 = id2[i].toInt() and 0xFF
            if (b1 != b2) {
                return b1 - b2
            }
        }
        return 0
    }
}