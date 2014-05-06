using System;
using System.Threading;
using System.Collections.Generic;
using System.Text;
using SharpPcap;
using SharpPcap.LibPcap;
using SharpPcap.AirPcap;
using SharpPcap.WinPcap;

namespace VoipTraifficDetect
{
    public class PCaptureService
    {
        private LibPcapLiveDevice mydevice = null;
        private string myDeviceIPAddr = "192.168.0.210";
        private static CaptureFileWriterDevice captureFileWriter;

        public PCaptureService(string TargetDeviceIPAddr)
        {
            // add IP addr check here later
            myDeviceIPAddr = TargetDeviceIPAddr;
        }

        //public static PCaptureService Service
        //{
        //    get { return SingletonProvider<PCaptureService>.Instance; }
        //}

        public void StartLogging(int mydurationInSeconds)
        {
            //show SharpPcap version
            string ver = SharpPcap.Version.VersionString;
            Console.WriteLine("SharpPcap {0}", ver);

            //obtain device List
            //WinPcapDevice
            CaptureDeviceList deviceList = CaptureDeviceList.Instance;
            if (deviceList.Count < 1)
            {
                Console.WriteLine("No devices were found on this machine");
                return;
            }

            // Retrieve the device list
            CaptureDeviceList devices = CaptureDeviceList.Instance;

            // If no devices were found print an error
            if (devices.Count < 1)
            {
                Console.WriteLine("No devices were found on this machine");
                return;
            }

            Console.WriteLine();
            Console.WriteLine("The following devices are available on this machine:");
            Console.WriteLine("----------------------------------------------------");
            Console.WriteLine();

            int i = 0;
            int readTimeoutMilliseconds = 1000;

            // Print out the devices
            foreach (LibPcapLiveDevice dev in devices)
            {
                /* Description */
                Console.WriteLine("{0}) {1} {2}", i, dev.Name, dev.Description);
                i++;
            }

            Console.WriteLine();
            Console.Write("-- Please choose a device to capture:");
            i = int.Parse(Console.ReadLine());

            LibPcapLiveDevice device = (LibPcapLiveDevice)devices[i];
            this.mydevice = device;
            //print device description
            Console.WriteLine("The device below will be used for packets capture:");
            Console.WriteLine("{0} {1}", device.Name, device.Description);
            //set path log
            //Console.Write("-- Please enter the output file name: ");
            //string capFile = Console.ReadLine();
            //string activeDir = @"C:\Program Files\Spirent Communications\TestDrive ULTS\OTAApplicationServer\Debug_Logs";
            //String assemblyPath = System.IO.Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location);
            string assemblyPath = @"C:\Program Files\Spirent Communications\TestDrive ULTS";
            string capFile = assemblyPath + @"\VOIPTrafficDetectTest.pcap";
            //string capFile = System.IO.Path.Combine(activeDir,"Pcap.pcap");
            // Register our handler function to the 'packet arrival' event
            device.OnPacketArrival +=
                new PacketArrivalEventHandler(device_OnPacketArrival);

            // Open the device for capturing
            //device.Open();
            LibPcapLiveDevice livePcapDevice = device as LibPcapLiveDevice;
            livePcapDevice.Open(DeviceMode.Promiscuous, readTimeoutMilliseconds);

            // tcpdump filter to capture only TCP/IP packets
            string filter = "udp";
            device.Filter = filter;
            Thread th = new Thread(new ParameterizedThreadStart(WaitForTimeout));
            th.Start(mydurationInSeconds);

            // Open or create a capture output file
            captureFileWriter = new CaptureFileWriterDevice(device, capFile);
            //device.DumpOpen(capFile);

            // Start capture 'INFINTE' number of packets
            device.StartCapture();


        }

        public void StopLogging()
        {
            lock (this)
            {

                try
                {
                    if (mydevice != null)
                    {
                        mydevice.OnPacketArrival -= device_OnPacketArrival;
                        try
                        {
                            mydevice.StopCaptureTimeout = new TimeSpan(0, 0, 60);
                            mydevice.StopCapture();
                        }
                        catch { }

                        try
                        {
                            mydevice.Close();
                        }
                        catch { }
                    }
                 }
                catch { }
                finally
                {
                    //IsLoggingStopped = true;
                    //captureFileWriter = null;
                    mydevice = null;
                }
            //}
            }
        }


        private void WaitForTimeout(object durationInSeconds)
        {
            System.Threading.Thread.Sleep((int)durationInSeconds*1000);
            this.StopLogging();
        }
        private LibPcapLiveDevice GetDeviceByIP(CaptureDeviceList deviceList, string ipAddr)
        {
            if (deviceList.Count != 0)
            {
                foreach (LibPcapLiveDevice myDevice in deviceList)
                {
                    if (myDevice.Addresses.Count > 0)
                    {
                        foreach (PcapAddress adr in myDevice.Addresses)
                        {
                            if (adr.Addr.ipAddress != null && !adr.Addr.ipAddress.IsIPv6LinkLocal)
                            {
                                if (adr.Addr.ipAddress.ToString().Equals(ipAddr))
                                {
                                    return myDevice;
                                }
                            }
                        }
                    }
                }
                return null;
            }
            else
            {
                return null;
            }
        }
        private  void device_OnPacketArrival(object sender, CaptureEventArgs e)
        {
            LibPcapLiveDevice device = (LibPcapLiveDevice)sender;

            //if device has a dump file opened
            //if (device.DumpOpened)
            //{
            //    //dump the packet to the file
            //    device.Dump(e.Packet);
            //    Console.WriteLine("Packet dumped to file.");
            //}
            if (captureFileWriter != null)
            {
                // write the packet to the file
                try
                {
                    captureFileWriter.Write(e.Packet);
                    Console.WriteLine("Packet dumped to file.");
                }
                catch { }
            }
        }
    }
}
