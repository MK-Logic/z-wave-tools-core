// SPDX-License-Identifier: BSD-3-Clause
// SPDX-FileCopyrightText: Z-Wave Alliance <https://z-wavealliance.org>
using System.Collections.Generic;
using System.Linq;
using NUnit.Framework;
using ZWave;
using ZWave.BasicApplication;
using ZWave.BasicApplication.Enums;
using ZWave.BasicApplication.Operations;
using ZWave.BasicApplication.Security;
using ZWave.CommandClasses;
using ZWave.Configuration;
using ZWave.Devices;
using ZWave.Enums;
using ZWave.Security;

namespace BasicApplicationTests.WakeOnCriticalMessage
{
    /// <summary>
    /// Controller Serial API: S2 is handled by the host, so the Notify Command is the outermost layer around S2.
    /// </summary>
    [TestFixture]
    public class WakeOnCriticalMessageS2Tests : TestBase
    {
        private const byte SEVERITY = 3;
        private readonly List<byte[]> _sentByFirst = new List<byte[]>();

        private static readonly byte[] TEST_SECRET_KEY = new byte[]
        {
            0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
            0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a
        };

        [SetUp]
        public void SetUp()
        {
            _transport.SetUpModulesNetwork(_ctrlFirst.SessionId, _ctrlSecond.SessionId);
            _ctrlFirst.MemoryGetId();
            _ctrlSecond.MemoryGetId();

            SetUpS2(_ctrlFirst, NODE_ID_2);
            SetUpS2(_ctrlSecond, NODE_ID_1);
            _ctrlFirst.SessionClient.AddSubstituteManager(new WakeOnCriticalMessageManager(_ctrlFirst.Network) { Severity = SEVERITY });
            _ctrlSecond.SessionClient.AddSubstituteManager(new WakeOnCriticalMessageManager(_ctrlSecond.Network));

            _sentByFirst.Clear();
            _app.FrameLayer.FrameTransmitted += (sender, e) =>
            {
                lock (_sentByFirst)
                {
                    if (e.Value.SessionId == _ctrlFirst.SessionId && e.Value.Data.Length > 4 &&
                        e.Value.Data[1] == (byte)CommandTypes.CmdZWaveSendData)
                    {
                        _sentByFirst.Add(e.Value.Data.Skip(4).Take(e.Value.Data[3]).ToArray());
                    }
                }
            };
        }

        private void SetUpS2(ZWave.BasicApplication.Devices.Controller ctrl, NodeTag peer)
        {
            var sm = new SecurityManager(ctrl.Network,
                new[]
                {
                    new NetworkKey(NKEY1_S2_C0), new NetworkKey(NKEY1_S2_C1), new NetworkKey(NKEY1_S2_C2), null, null, null, null, new NetworkKey(NKEY1_S0)
                },
                TEST_SECRET_KEY);
            ctrl.SessionClient.AddSubstituteManager(sm);
            ctrl.Network.IsEnabledS2_ACCESS = true;
            ctrl.Network.SetSecuritySchemes(peer, SecuritySchemeSet.ALLS2);
            ctrl.SessionClient.ExecuteAsync(sm.CreateSecurityS2ReportTask());
        }

        private ExpectDataResult SendCritical(byte[] primaryCmd)
        {
            var expectToken = _ctrlSecond.ExpectData(NODE_ID_1, primaryCmd, EXPECT_TIMEOUT, null);
            _ctrlFirst.SendData(NODE_ID_2, primaryCmd, TXO, new SubstituteSettings(SubstituteFlags.UseWakeOnCriticalMessage, 0));
            return (ExpectDataResult)expectToken.WaitCompletedSignal();
        }

        [Test]
        public void SendData_OutOfSync_OnlyNonceGetInNotifyAndReceiverDecryptsData()
        {
            // Arrange.
            byte[] primaryCmd = CreateDataAsBasicSet();

            // Act.
            var expectRes = SendCritical(primaryCmd);

            // Assert.
            Assert.IsTrue(expectRes);
            Assert.IsTrue(expectRes.Command.SequenceEqual(primaryCmd));
            AssertCmdSequence(_ctrlFirst.SessionId, new FrameLogRecord[]
            {
                FrameLogRecord.Create(NODE_ID_0, NODE_ID_2, COMMAND_CLASS_WAKE_ON_CRITICAL_MESSAGE.WAKE_ON_CRITICAL_MESSAGE_NOTIFY.ID),
                FrameLogRecord.Create(NODE_ID_2, NODE_ID_0, COMMAND_CLASS_SECURITY_2.SECURITY_2_NONCE_REPORT.ID),
                FrameLogRecord.Create(NODE_ID_0, NODE_ID_2, COMMAND_CLASS_SECURITY_2.SECURITY_2_MESSAGE_ENCAPSULATION.ID)
            });
            Assert.AreEqual(2, _sentByFirst.Count);
            AssertNotifyAround(_sentByFirst[0], COMMAND_CLASS_SECURITY_2.SECURITY_2_NONCE_GET.ID);
            Assert.AreEqual(COMMAND_CLASS_SECURITY_2.ID, _sentByFirst[1][0]);
        }

        [Test]
        public void SendData_InSync_S2EncapsulationInNotifyAndReceiverDecryptsData()
        {
            // Arrange: synchronize the SPAN with a regular S2 frame.
            byte[] primaryCmd = CreateDataAsBasicSet();
            var syncToken = _ctrlSecond.ExpectData(NODE_ID_1, primaryCmd, EXPECT_TIMEOUT, null);
            _ctrlFirst.SendData(NODE_ID_2, primaryCmd, TXO);
            Assert.IsTrue((ExpectDataResult)syncToken.WaitCompletedSignal());
            _sentByFirst.Clear();

            // Act.
            var expectRes = SendCritical(primaryCmd);

            // Assert.
            Assert.IsTrue(expectRes);
            Assert.IsTrue(expectRes.Command.SequenceEqual(primaryCmd));
            Assert.AreEqual(1, _sentByFirst.Count);
            AssertNotifyAround(_sentByFirst[0], COMMAND_CLASS_SECURITY_2.SECURITY_2_MESSAGE_ENCAPSULATION.ID);
        }

        private static void AssertNotifyAround(byte[] frame, byte innerCmdId)
        {
            Assert.AreEqual(COMMAND_CLASS_WAKE_ON_CRITICAL_MESSAGE.ID, frame[0]);
            Assert.AreEqual(COMMAND_CLASS_WAKE_ON_CRITICAL_MESSAGE.WAKE_ON_CRITICAL_MESSAGE_NOTIFY.ID, frame[1]);
            Assert.AreEqual(SEVERITY, frame[2]);
            Assert.AreEqual(frame.Length - 4, frame[3]);
            Assert.AreEqual(COMMAND_CLASS_SECURITY_2.ID, frame[4]);
            Assert.AreEqual(innerCmdId, frame[5]);
        }
    }
}
