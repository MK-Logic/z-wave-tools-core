// SPDX-License-Identifier: BSD-3-Clause
// SPDX-FileCopyrightText: Z-Wave Alliance <https://z-wavealliance.org>
using System;
using System.Collections.Generic;
using System.Linq;
using NUnit.Framework;
using Utils;
using ZWave.CommandClasses;
using ZWave.Security;
using ZWave.ZnifferApplication;

namespace ZnifferApplicationTests
{
    [TestFixture]
    public class WakeOnCriticalMessageParserTests
    {
        private const int SinglecastHeaderLength = 9;
        private const int LengthIndex = 7;
        private const int CrcLength = 2;
        private const byte Severity = 3;

        private static readonly byte[] NetworkKey = Tools.GetBytes("44 86 26 01 56 5E 15 A7 02 AC 7A 13 21 B2 4E 76");

        [SetUp]
        public void SetUp()
        {
            new S2DecodingTest().SetUp();
        }

        [Test]
        public void Parse_S2EncapsulationInNotify_DecryptsAndKeepsSpanInSync()
        {
            // Arrange: same S2 exchange as S2DecodingTest.SyncTest, with the first S2 Message Encapsulation in a Notify Command.
            DataItem nonceGet = CreateDataItem("E5 0E 8C 6C 01 41 09 0E 02 9F 01 EA D0 AE");
            DataItem nonceRpt = CreateDataItem("E5 0E 8C 6C 02 41 0C 1F 01 9F 02 FE 01 AE 01 28 B0 33 8D AE 49 22 B6 F7 6D A8 6F 25 A3 D4 D0");
            DataItem msgWSpan = CreateDataItem(WrapInNotify(Tools.GetBytes("E5 0E 8C 6C 01 41 0A 2B 02 9F 03 EB 01 12 41 AF 86 B0 22 77 70 F5 3A B7 4D B2 78 D0 BD DF C0 46 A0 BB 1F 87 6F EC DE 8A 0E A2 10")));
            DataItem msgNSpan = CreateDataItem("E5 0E 8C 6C 02 41 0D 20 01 9F 03 FF 00 AA F4 A0 1B 7B CE 10 2A 60 3A 9C 88 E6 EB ED F8 7B 09 B9");
            var sm = new SecurityManager();
            sm.AddSecurityKeys(new List<byte[]> { NetworkKey });

            // Act.
            foreach (var dataItem in new[] { nonceGet, nonceRpt, msgWSpan, msgNSpan })
            {
                WakeOnCriticalMessageParser.Parse(dataItem);
                sm.ParseSecurity(dataItem);
            }
            var decryptedWSpan = msgWSpan.Decrypt(sm);
            var decryptedNSpan = msgNSpan.Decrypt(sm);

            // Assert.
            Assert.AreEqual(COMMAND_CLASS_WAKE_ON_CRITICAL_MESSAGE.ID, msgWSpan.Payload[0]);
            Assert.AreEqual(2, msgWSpan.CarryPayload.Count);
            Assert.AreEqual(2, msgWSpan.GetCipherVersion());
            Assert.IsTrue(decryptedWSpan.IsDecrypted);
            Assert.AreEqual(Tools.GetBytes("86 11"), decryptedWSpan.Payload);
            Assert.IsTrue(decryptedNSpan.IsDecrypted);
            Assert.AreEqual(Tools.GetBytes("86 12 01 05 01 05 0E FF 00"), decryptedNSpan.Payload);
        }

        [Test]
        public void Parse_NonSecureNotify_AddsEncapsulatedPayloadOnce()
        {
            // Arrange: Notify Command with a Supervision Get (Basic Set).
            byte[] supervisionGet = Tools.GetBytes("6C 01 01 03 20 01 FF");
            DataItem dataItem = CreateDataItem(WrapInNotify(CreateFrame(supervisionGet)));

            // Act.
            bool isParsed = WakeOnCriticalMessageParser.Parse(dataItem);
            bool isParsedAgain = WakeOnCriticalMessageParser.Parse(dataItem);

            // Assert.
            Assert.IsTrue(isParsed);
            Assert.IsFalse(isParsedAgain);
            Assert.AreEqual(2, dataItem.CarryPayload.Count);
            Assert.AreEqual(supervisionGet, dataItem.LastPayload);
            Assert.AreEqual(COMMAND_CLASS_WAKE_ON_CRITICAL_MESSAGE.ID, dataItem.Payload[0]);
        }

        [Test]
        public void Parse_PayloadLengthMismatch_LeavesDataItemUnchanged()
        {
            // Arrange.
            byte[] frame = WrapInNotify(CreateFrame(Tools.GetBytes("6C 01 01 03 20 01 FF")));
            frame[SinglecastHeaderLength + 3]++;
            DataItem dataItem = CreateDataItem(frame);

            // Act.
            bool isParsed = WakeOnCriticalMessageParser.Parse(dataItem);

            // Assert.
            Assert.IsFalse(isParsed);
            Assert.AreEqual(1, dataItem.CarryPayload.Count);
            Assert.AreEqual(COMMAND_CLASS_WAKE_ON_CRITICAL_MESSAGE.ID, dataItem.LastPayload[0]);
        }

        [Test]
        public void Parse_NoNotify_LeavesDataItemUnchanged()
        {
            // Arrange.
            DataItem dataItem = CreateDataItem(CreateFrame(Tools.GetBytes("20 01 FF")));

            // Act.
            bool isParsed = WakeOnCriticalMessageParser.Parse(dataItem);

            // Assert.
            Assert.IsFalse(isParsed);
            Assert.AreEqual(1, dataItem.CarryPayload.Count);
        }

        private static DataItem CreateDataItem(string frame)
        {
            return CreateDataItem(Tools.GetBytes(frame));
        }

        private static DataItem CreateDataItem(byte[] frame)
        {
            return new DataItem(HeaderStore.H_SINGLECAST, 2, frame);
        }

        /// <summary>
        /// Creates a singlecast frame from node 1 to node 2 with a dummy CRC.
        /// </summary>
        private static byte[] CreateFrame(byte[] payload)
        {
            var frame = new List<byte>(Tools.GetBytes("E5 0E 8C 6C 01 41 01 00 02"));
            frame.AddRange(payload);
            frame.AddRange(new byte[CrcLength]);
            frame[LengthIndex] = (byte)frame.Count;
            return frame.ToArray();
        }

        /// <summary>
        /// Puts the payload of a singlecast frame into a Notify Command and fixes the frame length.
        /// </summary>
        private static byte[] WrapInNotify(byte[] frame)
        {
            int payloadLength = frame.Length - SinglecastHeaderLength - CrcLength;
            var notifyHeader = new byte[]
            {
                COMMAND_CLASS_WAKE_ON_CRITICAL_MESSAGE.ID,
                COMMAND_CLASS_WAKE_ON_CRITICAL_MESSAGE.WAKE_ON_CRITICAL_MESSAGE_NOTIFY.ID,
                Severity,
                (byte)payloadLength
            };
            byte[] ret = frame.Take(SinglecastHeaderLength).Concat(notifyHeader).Concat(frame.Skip(SinglecastHeaderLength)).ToArray();
            ret[LengthIndex] = (byte)ret.Length;
            return ret;
        }
    }
}
