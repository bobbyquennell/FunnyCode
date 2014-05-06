using System;
using System.Collections.Generic;
using System.Text;
using SharpPcap;
using System.Net;
using PacketDotNet;
using SharpPcap.LibPcap;
using SharpPcap.AirPcap;
using SharpPcap.WinPcap;


namespace VoipTraifficDetect
{
    public class VOIPDetect
    {
        ICaptureDevice myDevice;
        private string DestinationIP = "fd00:0:20:1:0:4543:484f:1";
        private string DestinationPort = "7000";
        public VOIPDetect()
        {
 
        }
        public void StartReadFile(string CapFilePath)
        {
            try
            {
                this.myDevice = new CaptureFileReaderDevice(CapFilePath);
                //open the device
                this.myDevice.Open();

            }
            catch (Exception error)
            {
                Console.WriteLine("Caught exception when opening file" + error.ToString());
                return;
            }

            //Register our handler function to the 'packet arrival' event
            //this.myDevice.OnPacketArrival +=
                //new PacketArrivalEventHandler(device_OnPacketArrival);

        }

        public void AnalyzePacketLog(out bool uplinkTrafficeExists, out bool downlinkTrafficeExists)
        {
            //bool isIPv6Address = VoLTEUtility.Service.IsIPv6Address(this.DestinationIP);
            ICaptureDevice device = this.myDevice;
            uplinkTrafficeExists = false;
            downlinkTrafficeExists = false;
            RawCapture packet;
            while ((packet = device.GetNextPacket()) != null)
            {
                //if (this.Direction == TransferDirection.Uplink)
                //{
                //    if (uplinkTrafficeExists)
                //    {
                //        break;
                //    }
                //}
                //else if (this.Direction == TransferDirection.DownLink)
                //{
                //    if (downlinkTrafficeExists)
                //    {
                //        break;
                //    }
                //}
                //else
                //{
                //    if (uplinkTrafficeExists && downlinkTrafficeExists)
                //    {
                //        break;
                //    }
                //}

                if (packet.LinkLayerType == PacketDotNet.LinkLayers.Ethernet)
                {
                    Packet p = PacketDotNet.Packet.ParsePacket(packet.LinkLayerType, packet.Data);

                    UdpPacket udpPacket = PacketDotNet.UdpPacket.GetEncapsulated(p);
                    //PacketDotNet.UdpPacket.GetEncapsulated(p);
                    if (udpPacket != null)
                    {
                        if (udpPacket.PayloadData != null)
                        {
                            GTPPacket gtp = GTPPacket.parse(udpPacket.PayloadData);
                            if (gtp != null)
                            {
                                int ipVersion = BigEndianBitsConverter.BigEndianBitsToUInt4(gtp.Payload, 0);
                                //if (isIPv6Address)
                                //{
                                    if (ipVersion == 6)
                                    {
                                        IPv6Packet p6 = null;
                                        try
                                        {
                                            p6 = new PacketDotNet.IPv6Packet(new PacketDotNet.Utils.ByteArraySegment(gtp.Payload));
                                        }
                                        catch { }

                                        if (p6 != null)
                                        {
                                            if (p6.DestinationAddress.Equals(IPAddress.Parse(this.DestinationIP)))
                                            {
                                                //Uplink
                                                Packet pp = p6.PayloadPacket;
                                                if (pp is UdpPacket)
                                                {
                                                    ushort dPort = (pp as UdpPacket).DestinationPort;
                                                    string[] portList = this.DestinationPort.Split('-');
                                                    if (portList.Length > 1)
                                                    {
                                                        if (ushort.Parse(portList[0]) <= dPort && dPort <= ushort.Parse(portList[1]))
                                                        {
                                                            uplinkTrafficeExists = true;
                                                            continue;
                                                        }
                                                    }
                                                    else
                                                    {
                                                        if (ushort.Parse(portList[0]) == dPort)
                                                        {
                                                            uplinkTrafficeExists = true;
                                                            continue;
                                                        }
                                                    }
                                                }
                                                else if (pp is TcpPacket)
                                                {
                                                    ushort dPort = (pp as TcpPacket).DestinationPort;
                                                    string[] portList = this.DestinationPort.Split('-');
                                                    if (portList.Length > 1)
                                                    {
                                                        if (ushort.Parse(portList[0]) <= dPort && dPort <= ushort.Parse(portList[1]))
                                                        {
                                                            uplinkTrafficeExists = true;
                                                            continue;
                                                        }
                                                    }
                                                    else
                                                    {
                                                        if (ushort.Parse(portList[0]) == dPort)
                                                        {
                                                            uplinkTrafficeExists = true;
                                                            continue;
                                                        }
                                                    }
                                                }
                                            }
                                            else if (p6.SourceAddress.Equals(IPAddress.Parse(this.DestinationIP)))
                                            {
                                                //Downlink
                                                Packet pp = p6.PayloadPacket;
                                                if (pp is UdpPacket)
                                                {
                                                    ushort sPort = (pp as UdpPacket).SourcePort;
                                                    string[] portList = this.DestinationPort.Split('-');
                                                    if (portList.Length > 1)
                                                    {
                                                        if (ushort.Parse(portList[0]) <= sPort && sPort <= ushort.Parse(portList[1]))
                                                        {
                                                            downlinkTrafficeExists = true;
                                                            continue;
                                                        }
                                                    }
                                                    else
                                                    {
                                                        if (ushort.Parse(portList[0]) == sPort)
                                                        {
                                                            downlinkTrafficeExists = true;
                                                            continue;
                                                        }
                                                    }
                                                }
                                                else if (pp is TcpPacket)
                                                {
                                                    ushort sPort = (pp as TcpPacket).SourcePort;
                                                    string[] portList = this.DestinationPort.Split('-');
                                                    if (portList.Length > 1)
                                                    {
                                                        if (ushort.Parse(portList[0]) <= sPort && sPort <= ushort.Parse(portList[1]))
                                                        {
                                                            downlinkTrafficeExists = true;
                                                            continue;
                                                        }
                                                    }
                                                    else
                                                    {
                                                        if (ushort.Parse(portList[0]) == sPort)
                                                        {
                                                            downlinkTrafficeExists = true;
                                                            continue;
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                //}
                                else
                                {
                                    if (ipVersion == 4)
                                    {
                                        IPv4Packet p4 = null;
                                        try
                                        {
                                            p4 = new PacketDotNet.IPv4Packet(new PacketDotNet.Utils.ByteArraySegment(gtp.Payload));
                                        }
                                        catch { }

                                        if (p4 != null)
                                        {
                                            if (p4.DestinationAddress.Equals(IPAddress.Parse(this.DestinationIP)))
                                            {
                                                //Uplink
                                                Packet pp = p4.PayloadPacket;
                                                if (pp is UdpPacket)
                                                {
                                                    ushort dPort = (pp as UdpPacket).DestinationPort;
                                                    string[] portList = this.DestinationPort.Split('-');
                                                    if (portList.Length > 1)
                                                    {
                                                        if (ushort.Parse(portList[0]) <= dPort && dPort <= ushort.Parse(portList[1]))
                                                        {
                                                            uplinkTrafficeExists = true;
                                                            continue;
                                                        }
                                                    }
                                                    else
                                                    {
                                                        if (ushort.Parse(portList[0]) == dPort)
                                                        {
                                                            uplinkTrafficeExists = true;
                                                            continue;
                                                        }
                                                    }
                                                }
                                            }
                                            else if (p4.SourceAddress.Equals(IPAddress.Parse(this.DestinationIP)))
                                            {
                                                //Downlink
                                                Packet pp = p4.PayloadPacket;
                                                if (pp is UdpPacket)
                                                {
                                                    ushort sPort = (pp as UdpPacket).SourcePort;
                                                    string[] portList = this.DestinationPort.Split('-');
                                                    if (portList.Length > 1)
                                                    {
                                                        if (ushort.Parse(portList[0]) <= sPort && sPort <= ushort.Parse(portList[1]))
                                                        {
                                                            downlinkTrafficeExists = true;
                                                            continue;
                                                        }
                                                    }
                                                    else
                                                    {
                                                        if (ushort.Parse(portList[0]) == sPort)
                                                        {
                                                            downlinkTrafficeExists = true;
                                                            continue;
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }

                            }
                        }
                    }
                }
            }
        }

        private static void device_OnPacketArrival(object sender, CaptureEventArgs e)
        {
            //if (e.Packet.LinkLayerType == PacketDotNet.LinkLayers.Ethernet)
            //{
            //    Packet packet = PacketDotNet.Packet.ParsePacket(e.Packet);
            //    EthernetPacket ethernetPacket = (PacketDotNet.EthernetPacket)packet;

            //    Console.WriteLine("At: {0}:{1}: MAC:{2} -> MAC:{3}",
            //        ethernetPacket.Timeval.Date.ToString(),
            //        ethernetPacket.Timeval.Date.Millisecond,
            //        ethernetPacket.SourceHwAddress,
            //        ethernetPacket.DestinationHwAddress);
            //}
        }

    }
}
