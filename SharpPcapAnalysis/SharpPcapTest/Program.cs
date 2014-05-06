using System;
using System.Collections.Generic;
using System.Text;
using System.Linq;
//using System.Text;
using VoipTraifficDetect;
//using SharpPcap;


namespace SharpPcapTest
{
    class Program
    {
        static void Main(string[] args)
        {
            string iPAddress = "10.61.20.67";
            string assemblyPath = @"C:\Program Files\Spirent Communications\TestDrive ULTS";
            string capFile = assemblyPath + @"\VOIPTrafficDetectTest.pcap";
            //string capFile = assemblyPath + @"\port mirror RTP Log.pcap";
            PCaptureService myPcap = new PCaptureService(iPAddress);
            VOIPDetect myDetect = new VOIPDetect();
            myPcap.StartLogging(20);
            System.Threading.Thread.Sleep(30 * 1000);

            myDetect.StartReadFile(capFile);
            bool isUPTrafficExisted = false;
            bool isDLTrafficExisted = false;
            myDetect.AnalyzePacketLog(out isUPTrafficExisted, out isDLTrafficExisted);

            Console.WriteLine("{0},{1}", isUPTrafficExisted, isDLTrafficExisted);
            // Wait for 'Enter' from the user.
            Console.WriteLine("-- Press Enter to stop Capture.");
            Console.ReadLine();

            // Stop the capturing process

            Console.WriteLine("-- Capture stopped.");

        }

    }
}

