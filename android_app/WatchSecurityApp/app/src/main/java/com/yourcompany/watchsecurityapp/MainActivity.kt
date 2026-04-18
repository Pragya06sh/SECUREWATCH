package com.yourcompany.watchsecurityapp

import android.Manifest
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothManager
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Bundle
import android.widget.ArrayAdapter
import android.widget.Button
import android.widget.ListView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import okhttp3.OkHttpClient
import okhttp3.Request

class MainActivity : AppCompatActivity() {

    private lateinit var bluetoothAdapter: BluetoothAdapter
    private lateinit var deviceListView: ListView
    private lateinit var scanButton: Button

    private val deviceList = ArrayList<String>()
    private lateinit var adapter: ArrayAdapter<String>

    // Bluetooth Receiver
    private val receiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {

            val action = intent.action

            if (BluetoothDevice.ACTION_FOUND == action) {

                val device: BluetoothDevice? =
                    intent.getParcelableExtra(BluetoothDevice.EXTRA_DEVICE)

                device?.let {

                    val deviceName = it.name ?: "Unknown Device"
                    val deviceAddress = it.address
                    val deviceType = it.type
                    val timestamp = System.currentTimeMillis()

                    verifyDevice(deviceAddress, deviceName, deviceType, timestamp)

                    val deviceInfo = "Device: $deviceName\nMAC: $deviceAddress"

                    if (!deviceList.contains(deviceInfo)) {
                        deviceList.add(deviceInfo)
                        adapter.notifyDataSetChanged()
                    }
                }
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        scanButton = findViewById(R.id.scanButton)
        deviceListView = findViewById(R.id.deviceList)

        adapter = ArrayAdapter(this, android.R.layout.simple_list_item_1, deviceList)
        deviceListView.adapter = adapter

        val bluetoothManager = getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager
        bluetoothAdapter = bluetoothManager.adapter

        requestPermissions()

        scanButton.setOnClickListener {

            deviceList.clear()
            adapter.notifyDataSetChanged()

            val filter = IntentFilter(BluetoothDevice.ACTION_FOUND)
            registerReceiver(receiver, filter)

            bluetoothAdapter.startDiscovery()
        }
    }

    private fun requestPermissions() {

        val permissions = arrayOf(
            Manifest.permission.ACCESS_FINE_LOCATION,
            Manifest.permission.BLUETOOTH_SCAN,
            Manifest.permission.BLUETOOTH_CONNECT
        )

        ActivityCompat.requestPermissions(this, permissions, 1)
    }

    override fun onDestroy() {
        super.onDestroy()
        unregisterReceiver(receiver)
    }

    // Backend API Call
    fun verifyDevice(
        deviceAddress: String,
        deviceName: String,
        deviceType: Int,
        timestamp: Long
    ) {

        val client = okhttp3.OkHttpClient()

        val url =
            "http://10.114.19.10:8000/verify-device?" +
                    "device_id=$deviceAddress" +
                    "&device_name=$deviceName" +
                    "&device_type=$deviceType" +
                    "&timestamp=$timestamp"

        val request = okhttp3.Request.Builder()
            .url(url)
            .build()

        Thread {

            try {

                val response = client.newCall(request).execute()
                val responseData = response.body?.string()

                runOnUiThread {

                    if(responseData!!.contains("quarantined\":true")){

                        Toast.makeText(
                            this,
                            "🚨 DEVICE QUARANTINED: Possible Smartwatch Hack",
                            Toast.LENGTH_LONG
                        ).show()

                    }

                }

            } catch (e: Exception) {

                runOnUiThread {

                    android.widget.Toast.makeText(
                        this,
                        "Server Error",
                        android.widget.Toast.LENGTH_LONG
                    ).show()

                }

            }

        }.start()
    }
}