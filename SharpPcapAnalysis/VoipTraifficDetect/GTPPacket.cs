using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Text;

namespace VoipTraifficDetect
{
    class GTPPacket
    {
        #region Enums



        #endregion

        #region Constructors

        public GTPPacket()
        {

        }

        #endregion

        #region Properties

        private ushort version = 1;
        //3 bits
        public ushort Version
        {
            get { return version; }
            set { version = value; }
        }

        private ushort protocolType = 1;
        //1 bit
        public ushort ProtocolType
        {
            get { return protocolType; }
            set { protocolType = value; }
        }

        private ushort reserved = 0;
        //1 bit
        public ushort Reserved
        {
            get { return reserved; }
            set { reserved = value; }
        }

        private bool extensionHeaderFlag = false;
        //1 bit
        public bool ExtensionHeaderFlag
        {
            get { return extensionHeaderFlag; }
            set { extensionHeaderFlag = value; }
        }

        private bool sequenceNumberFlag = false;
        //1 bit
        public bool SequenceNumberFlag
        {
            get { return sequenceNumberFlag; }
            set { sequenceNumberFlag = value; }
        }

        private bool n_PDUNumberFlag = false;
        //1 bit
        public bool N_PDUNumberFlag
        {
            get { return n_PDUNumberFlag; }
            set { n_PDUNumberFlag = value; }
        }

        private ushort messageType = 0xff;
        //8 bits
        public ushort MessageType
        {
            get { return messageType; }
            set { messageType = value; }
        }

        private ushort length = 0;
        //16 bits
        public ushort Length
        {
            get { return length; }
            set { length = value; }
        }

        private uint tunnelEndpointId = 0;
        //32 bits
        public uint TunnelEndpointId
        {
            get { return tunnelEndpointId; }
            set { tunnelEndpointId = value; }
        }

        private ushort sequenceNumber = 0x0000;
        //16 bits
        public ushort SequenceNumber
        {
            get { return sequenceNumber; }
            set { sequenceNumber = value; }
        }

        private ushort n_PDUNumber = 0x00;
        //8 bits
        public ushort N_PDUNumber
        {
            get { return n_PDUNumber; }
            set { n_PDUNumber = value; }
        }

        private ushort nextExtensionHeaderType = 0x00;
        //8 bits
        public ushort NextExtensionHeaderType
        {
            get { return nextExtensionHeaderType; }
            set { nextExtensionHeaderType = value; }
        }

        private byte[] payload = new byte[0];
        //any bits
        public byte[] Payload
        {
            get { return payload; }
            set { payload = value; }
        }

        #endregion

        #region Methods

        public static GTPPacket parse(byte[] rawData)
        {
            GTPPacket gtp = new GTPPacket();
            int currentByteIndex = 0;

            //First Byte
            BitVector32 bv = new BitVector32(rawData[0]);
            BitVector32.Section s1 = BitVector32.CreateSection(0x1); //N_PDUNumberFlag
            BitVector32.Section s2 = BitVector32.CreateSection(0x1, s1); //SequenceNumberFlag
            BitVector32.Section s3 = BitVector32.CreateSection(0x1, s2); //ExtensionHeaderFlag
            BitVector32.Section s4 = BitVector32.CreateSection(0x1, s3); //Reserved
            BitVector32.Section s5 = BitVector32.CreateSection(0x1, s4); //ProtocolType
            BitVector32.Section s6 = BitVector32.CreateSection(0x1, s5); //Version

            gtp.version = (ushort)bv[s6];

            if (gtp.version != 1)
            {
                return null;
            }

            gtp.protocolType = (ushort)bv[s5];

            gtp.reserved = (ushort)bv[s4];

            gtp.extensionHeaderFlag = bv[s3] == 0 ? false : true;
            gtp.sequenceNumberFlag = bv[s2] == 0 ? false : true;
            gtp.n_PDUNumberFlag = bv[s1] == 0 ? false : true;

            currentByteIndex += 1;

            //Message Type - 8 bits
            gtp.messageType = BigEndianBitsConverter.BigEndianBitsToUInt8(rawData, currentByteIndex);

            currentByteIndex += 1;

            gtp.length = BigEndianBitsConverter.BigEndianBitsToUInt16(rawData, currentByteIndex);

            if (gtp.Length != rawData.Length - 8)
            {
                return null;
            }

            currentByteIndex += 2;

            gtp.tunnelEndpointId = BigEndianBitsConverter.BigEndianBitsToUInt32(rawData, currentByteIndex);

            currentByteIndex += 4;

            if (gtp.extensionHeaderFlag || gtp.sequenceNumberFlag || gtp.n_PDUNumberFlag)
            {
                gtp.sequenceNumber = BigEndianBitsConverter.BigEndianBitsToUInt16(rawData, currentByteIndex);

                currentByteIndex += 2;

                gtp.n_PDUNumber = BigEndianBitsConverter.BigEndianBitsToUInt8(rawData, currentByteIndex);

                currentByteIndex += 1;

                gtp.nextExtensionHeaderType = BigEndianBitsConverter.BigEndianBitsToUInt8(rawData, currentByteIndex);

                currentByteIndex += 1;

                if (gtp.nextExtensionHeaderType != 0)
                {
                    //continue to decode extension header
                    while (true)
                    {
                        ushort len = BigEndianBitsConverter.BigEndianBitsToUInt8(rawData, currentByteIndex);
                        currentByteIndex += 1;
                        if ((len <= 16) || (len % 4 != 0))
                        {
                            return null;
                        }

                        //ignore contents here
                        currentByteIndex += len - 1;

                        ushort nextheader = BigEndianBitsConverter.BigEndianBitsToUInt8(rawData, currentByteIndex);

                        currentByteIndex += 1;
                    }
                }
            }

            gtp.payload = new byte[rawData.Length - currentByteIndex];
            Array.Copy(rawData, currentByteIndex, gtp.payload, 0, rawData.Length - currentByteIndex);

            return gtp;
        }

        #endregion
    }
}
