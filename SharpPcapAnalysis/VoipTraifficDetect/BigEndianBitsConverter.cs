using System;
using System.Collections.Generic;
using System.Text;
using System.Collections.Specialized;

namespace VoipTraifficDetect
{
    class BigEndianBitsConverter
    {
        public static int BigEndianBitsToInt32(byte[] rawData, int startByteIndex)
        {
            BitVector32 bv = new BitVector32(0);
            bv[rawData[startByteIndex + 3]] = true;
            bv[rawData[startByteIndex + 2] << 8] = true;
            bv[rawData[startByteIndex + 1] << 16] = true;
            bv[rawData[startByteIndex] << 24] = true;
            return bv.Data;
        }

        public static uint BigEndianBitsToUInt32(byte[] rawData, int startByteIndex)
        {
            BitVector32 bv = new BitVector32(0);
            bv[rawData[startByteIndex + 3]] = true;
            bv[rawData[startByteIndex + 2] << 8] = true;
            bv[rawData[startByteIndex + 1] << 16] = true;
            bv[rawData[startByteIndex] << 24] = true;
            return (uint)bv.Data;
        }

        public static ushort BigEndianBitsToUInt16(byte[] rawData, int startByteIndex)
        {
            BitVector32 bv = new BitVector32(0);
            bv[rawData[startByteIndex + 1]] = true;
            bv[rawData[startByteIndex] << 8] = true;
            BitVector32.Section s1 = BitVector32.CreateSection(0x7fff);
            return (ushort)bv[s1];
        }

        public static ushort BigEndianBitsToUInt8(byte[] rawData, int startByteIndex)
        {
            BitVector32 bv = new BitVector32(0);
            bv[rawData[startByteIndex]] = true;
            return (ushort)bv.Data;
        }

        public static ushort BigEndianBitsToUInt4(byte[] rawData, int startByteIndex)
        {
            BitVector32 bv = new BitVector32(0);
            bv[rawData[startByteIndex] >> 4] = true;
            return (ushort)bv.Data;
        }

        public static void BigEndianCopyInt32(byte[] rawData, int startByteIndex, int value)
        {
            rawData[startByteIndex + 0] = (byte)(value >> 24);
            rawData[startByteIndex + 1] = (byte)(value >> 16);
            rawData[startByteIndex + 2] = (byte)(value >> 8);
            rawData[startByteIndex + 3] = (byte)(value);
        }

        public static void BigEndianCopyUInt32(byte[] rawData, int startByteIndex, uint value)
        {
            rawData[startByteIndex + 0] = (byte)(value >> 24);
            rawData[startByteIndex + 1] = (byte)(value >> 16);
            rawData[startByteIndex + 2] = (byte)(value >> 8);
            rawData[startByteIndex + 3] = (byte)(value);
        }

        public static void BigEndianCopyInt16(byte[] rawData, int startByteIndex, short value)
        {
            rawData[startByteIndex + 0] = (byte)(value >> 8);
            rawData[startByteIndex + 1] = (byte)(value);
        }

        public static void BigEndianCopyUInt16(byte[] rawData, int startByteIndex, ushort value)
        {
            rawData[startByteIndex + 0] = (byte)(value >> 8);
            rawData[startByteIndex + 1] = (byte)(value);
        }
    }
}
