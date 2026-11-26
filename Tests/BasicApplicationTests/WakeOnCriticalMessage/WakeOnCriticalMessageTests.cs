// SPDX-License-Identifier: BSD-3-Clause
// SPDX-FileCopyrightText: Z-Wave Alliance <https://z-wavealliance.org>
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using NUnit.Framework;
using ZWave;
using ZWave.BasicApplication;
using ZWave.BasicApplication.Enums;
using ZWave.BasicApplication.Operations;
using ZWave.CommandClasses;
using ZWave.Devices;
using ZWave.Enums;
using ZWave.Layers.Frame;

namespace BasicApplicationTests.WakeOnCriticalMessage
{
    [TestFixture]
    public class WakeOnCriticalMessageTests : TestBase
    {
        private const byte SEVERITY = 5;
        // S2 Message Encapsulation (sequence number, no extensions) with dummy ciphertext and MAC.
        private static readonly byte[] S2_MESSAGE_ENCAPSULATION =
        {
            COMMAND_CLASS_SECURITY_2.ID, COMMAND_CLASS_SECURITY_2.SECURITY_2_MESSAGE_ENCAPSULATION.ID, 0x01, 0x00,
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB
        };
        // S2 Message Encapsulation with a SPAN Extension (critical, 16 bytes sender entropy input),
        // followed by dummy ciphertext and MAC.
        private static readonly byte[] S2_MESSAGE_ENCAPSULATION_WITH_SPAN =
        {
            COMMAND_CLASS_SECURITY_2.ID, COMMAND_CLASS_SECURITY_2.SECURITY_2_MESSAGE_ENCAPSULATION.ID, 0x01, 0x01,
            0x12, 0x41,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB
        };
        private readonly List<byte[]> _sentByFirst = new List<byte[]>();
        private WakeOnCriticalMessageManager _wocmFirst;
        private WakeOnCriticalMessageManager _wocmSecond;

        [SetUp]
        public void SetUp()
        {
            _transport.SetUpModulesNetwork(_ctrlFirst.SessionId, _ctrlSecond.SessionId);
            _wocmFirst = new WakeOnCriticalMessageManager(_ctrlFirst.Network);
            _wocmSecond = new WakeOnCriticalMessageManager(_ctrlSecond.Network);
            _ctrlFirst.SessionClient.AddSubstituteManager(_wocmFirst);
            _ctrlSecond.SessionClient.AddSubstituteManager(_wocmSecond);

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

        [Test]
        public void Incoming_Notify_ReceiverGetsEncapsulatedCommand()
        {
            // Arrange.
            byte[] primaryCmd = CreateDataAsBasicSet();
            var expectToken = _ctrlSecond.ExpectData(NODE_ID_1, primaryCmd, EXPECT_TIMEOUT, null);

            // Act.
            _ctrlFirst.SendData(NODE_ID_2, Notify(SEVERITY, primaryCmd), TXO);
            var expectRes = (ExpectDataResult)expectToken.WaitCompletedSignal();

            // Assert.
            Assert.IsTrue(expectRes);
            Assert.IsTrue(expectRes.Command.SequenceEqual(primaryCmd));
            Assert.IsTrue(expectRes.SubstituteIncomingFlags.HasFlag(SubstituteIncomingFlags.WakeOnCriticalMessage));
            Assert.AreEqual(SEVERITY, expectRes.WakeOnCriticalMessageSeverity);
        }

        [Test]
        public void Incoming_NoNotify_NoFlagAndNoSeverity()
        {
            // Arrange.
            byte[] primaryCmd = CreateDataAsBasicSet();
            var expectToken = _ctrlSecond.ExpectData(NODE_ID_1, primaryCmd, EXPECT_TIMEOUT, null);

            // Act.
            _ctrlFirst.SendData(NODE_ID_2, primaryCmd, TXO);
            var expectRes = (ExpectDataResult)expectToken.WaitCompletedSignal();

            // Assert.
            Assert.IsTrue(expectRes);
            Assert.IsFalse(expectRes.SubstituteIncomingFlags.HasFlag(SubstituteIncomingFlags.WakeOnCriticalMessage));
            Assert.IsNull(expectRes.WakeOnCriticalMessageSeverity);
        }

        [Test]
        public void Incoming_PayloadLengthMismatch_ReceiverGetsNotifyUnchanged()
        {
            // Arrange.
            byte[] notify = Notify(SEVERITY, CreateDataAsBasicSet());
            notify[3]++;
            var expectToken = _ctrlSecond.ExpectData(NODE_ID_1, notify, EXPECT_TIMEOUT, null);

            // Act.
            _ctrlFirst.SendData(NODE_ID_2, notify, TXO);
            var expectRes = (ExpectDataResult)expectToken.WaitCompletedSignal();

            // Assert.
            Assert.IsTrue(expectRes);
            Assert.IsTrue(expectRes.Command.SequenceEqual(notify));
            Assert.IsFalse(expectRes.SubstituteIncomingFlags.HasFlag(SubstituteIncomingFlags.WakeOnCriticalMessage));
            Assert.IsNull(expectRes.WakeOnCriticalMessageSeverity);
        }

        [Test]
        public void Incoming_Suspended_ReceiverGetsNotifyUnchanged()
        {
            // Arrange.
            _wocmSecond.Suspend();
            byte[] notify = Notify(SEVERITY, CreateDataAsBasicSet());
            var expectToken = _ctrlSecond.ExpectData(NODE_ID_1, notify, EXPECT_TIMEOUT, null);

            // Act.
            _ctrlFirst.SendData(NODE_ID_2, notify, TXO);
            var expectRes = (ExpectDataResult)expectToken.WaitCompletedSignal();

            // Assert.
            Assert.IsTrue(expectRes);
            Assert.IsTrue(expectRes.Command.SequenceEqual(notify));
            Assert.IsFalse(expectRes.SubstituteIncomingFlags.HasFlag(SubstituteIncomingFlags.WakeOnCriticalMessage));
            Assert.IsNull(expectRes.WakeOnCriticalMessageSeverity);
        }

        [Test]
        public void Outgoing_Severity_NotifySentAndDecapsulatedByReceiver()
        {
            // Arrange.
            byte[] primaryCmd = CreateDataAsBasicSet();
            var expectToken = _ctrlSecond.ExpectData(NODE_ID_1, primaryCmd, EXPECT_TIMEOUT, null);

            // Act.
            _ctrlFirst.SendData(NODE_ID_2, primaryCmd, TXO, Settings(SEVERITY));
            var expectRes = (ExpectDataResult)expectToken.WaitCompletedSignal();

            // Assert.
            Assert.IsTrue(expectRes);
            Assert.IsTrue(expectRes.Command.SequenceEqual(primaryCmd));
            Assert.AreEqual(1, _sentByFirst.Count);
            Assert.IsTrue(_sentByFirst[0].SequenceEqual(Notify(SEVERITY, primaryCmd)));
        }

        [Test]
        public void SubstituteActionInternal_SeverityZero_WrapsDataForNegativeTesting()
        {
            // Arrange.
            var network = new NetworkViewPoint();
            byte[] primaryCmd = CreateDataAsBasicSet();
            var action = new SendDataOperation(network, NODE_ID_2, primaryCmd, TXO) { SubstituteSettings = Settings(0) };

            // Act.
            var result = new WakeOnCriticalMessageManager(network).SubstituteActionInternal(action);

            // Assert.
            Assert.AreSame(action, result);
            Assert.IsTrue(action.Data.SequenceEqual(Notify(0, primaryCmd)));
        }

        [Test]
        public void SubstituteActionInternal_Suspended_LeavesActionUnchanged()
        {
            // Arrange.
            var network = new NetworkViewPoint();
            byte[] primaryCmd = CreateDataAsBasicSet();
            var action = new SendDataOperation(network, NODE_ID_2, primaryCmd, TXO) { SubstituteSettings = Settings(SEVERITY) };
            var manager = new WakeOnCriticalMessageManager(network);
            manager.Suspend();

            // Act.
            var result = manager.SubstituteActionInternal(action);

            // Assert.
            Assert.IsNull(result);
            Assert.IsTrue(action.Data.SequenceEqual(primaryCmd));
        }

        [Test]
        public void SubstituteActionInternal_S2WithoutSpanExtension_WrapsData()
        {
            // Arrange.
            var network = new NetworkViewPoint();
            var action = new SendDataOperation(network, NODE_ID_2, S2_MESSAGE_ENCAPSULATION, TXO) { SubstituteSettings = Settings(SEVERITY) };

            // Act.
            var result = new WakeOnCriticalMessageManager(network).SubstituteActionInternal(action);

            // Assert.
            Assert.AreSame(action, result);
            Assert.IsTrue(action.Data.SequenceEqual(Notify(SEVERITY, S2_MESSAGE_ENCAPSULATION)));
        }

        [Test]
        public void SubstituteActionInternal_S2WithSpanExtension_LeavesActionUnchanged()
        {
            // Arrange: an S2 Message Encapsulation in a Notify Command MUST NOT carry a SPAN Extension
            // (CC:008D.01.04.11.013).
            var network = new NetworkViewPoint();
            var action = new SendDataOperation(network, NODE_ID_2, S2_MESSAGE_ENCAPSULATION_WITH_SPAN, TXO) { SubstituteSettings = Settings(SEVERITY) };

            // Act.
            var result = new WakeOnCriticalMessageManager(network).SubstituteActionInternal(action);

            // Assert.
            Assert.IsNull(result);
            Assert.IsTrue(action.Data.SequenceEqual(S2_MESSAGE_ENCAPSULATION_WITH_SPAN));
        }

        [Test]
        public void SubstituteActionInternal_NoSeverity_LeavesActionUnchanged()
        {
            // Arrange.
            var network = new NetworkViewPoint();
            byte[] primaryCmd = CreateDataAsBasicSet();
            var action = new SendDataOperation(network, NODE_ID_2, primaryCmd, TXO);

            // Act.
            var result = new WakeOnCriticalMessageManager(network).SubstituteActionInternal(action);

            // Assert.
            Assert.IsNull(result);
            Assert.IsTrue(action.Data.SequenceEqual(primaryCmd));
        }

        [Test]
        public void SubstituteActionInternal_EndDeviceNonSecure_WrapsData()
        {
            // Arrange.
            var network = new NetworkViewPoint { Library = Libraries.EndDeviceLib };
            byte[] primaryCmd = CreateDataAsBasicSet();
            var action = new SendDataExOperation(network, NODE_ID_2, primaryCmd, TXO, SecuritySchemes.NONE) { SubstituteSettings = Settings(SEVERITY) };

            // Act.
            var result = new WakeOnCriticalMessageManager(network).SubstituteActionInternal(action);

            // Assert.
            Assert.AreSame(action, result);
            Assert.IsTrue(action.Data.SequenceEqual(Notify(SEVERITY, primaryCmd)));
        }

        [Test]
        public void SubstituteActionInternal_EndDeviceS2_ReplacesActionWithRejection()
        {
            // Arrange: the End Device firmware encrypts the frame, so the Notify Command would end up inside S2.
            var network = new NetworkViewPoint { Library = Libraries.EndDeviceLib };
            byte[] primaryCmd = CreateDataAsBasicSet();
            var action = new SendDataExOperation(network, NODE_ID_2, primaryCmd, TXO, SecuritySchemes.S2_ACCESS) { SubstituteSettings = Settings(SEVERITY) };

            // Act.
            var result = new WakeOnCriticalMessageManager(network).SubstituteActionInternal(action);

            // Assert.
            Assert.IsNotNull(result);
            Assert.AreNotSame(action, result);
            Assert.IsTrue(action.Data.SequenceEqual(primaryCmd));
        }

        [Test]
        public void Outgoing_EndDeviceS2_FailsWithoutSending()
        {
            // Arrange.
            _ctrlFirst.Network.Library = Libraries.EndDeviceLib;
            int sentDataExCount = 0;
            _app.FrameLayer.FrameTransmitted += (sender, e) =>
            {
                if (e.Value.SessionId == _ctrlFirst.SessionId && e.Value.Data.Length > 1 &&
                    e.Value.Data[1] == (byte)CommandTypes.CmdZWaveSendDataEx)
                {
                    Interlocked.Increment(ref sentDataExCount);
                }
            };

            // Act.
            var result = _ctrlFirst.SendDataEx(NODE_ID_2, CreateDataAsBasicSet(), TXO,
                Settings(SEVERITY),
                TransmitSecurityOptions.S2_TXOPTION_VERIFY_DELIVERY, SecuritySchemes.S2_ACCESS, TransmitOptions2.NONE);

            // Assert.
            Assert.AreEqual(ActionStates.Failed, result.State);
            Assert.AreEqual(0, sentDataExCount);
        }

        [Test]
        public void Incoming_EndDeviceNonSecure_ReceiverGetsEncapsulatedCommand()
        {
            // Arrange.
            _ctrlSecond.Network.Library = Libraries.EndDeviceLib;
            byte[] primaryCmd = CreateDataAsBasicSet();
            var expectToken = _ctrlSecond.ExpectData(NODE_ID_1, primaryCmd, EXPECT_TIMEOUT, null);

            // Act.
            _ctrlFirst.SendData(NODE_ID_2, Notify(SEVERITY, primaryCmd), TXO);
            var expectRes = (ExpectDataResult)expectToken.WaitCompletedSignal();

            // Assert.
            Assert.IsTrue(expectRes);
            Assert.IsTrue(expectRes.Command.SequenceEqual(primaryCmd));
        }

        [Test]
        public void Incoming_EndDeviceS2_ReceiverGetsNotifyUnchanged()
        {
            // Arrange: the End Device firmware hasn't seen the S2 encapsulation, so the host can't process it.
            _ctrlSecond.Network.Library = Libraries.EndDeviceLib;
            byte[] notify = Notify(SEVERITY, S2_MESSAGE_ENCAPSULATION);
            var expectToken = _ctrlSecond.ExpectData(NODE_ID_1, notify, EXPECT_TIMEOUT, null);

            // Act.
            _ctrlFirst.SendData(NODE_ID_2, notify, TXO);
            var expectRes = (ExpectDataResult)expectToken.WaitCompletedSignal();

            // Assert.
            Assert.IsTrue(expectRes);
            Assert.IsTrue(expectRes.Command.SequenceEqual(notify));
        }

        [Test]
        public void Incoming_ControllerS2_ReceiverGetsEncapsulatedCommand()
        {
            // Arrange: on a controller the S2 encapsulation is handled by the host, so it is decapsulated.
            var expectToken = _ctrlSecond.ExpectData(NODE_ID_1, S2_MESSAGE_ENCAPSULATION, EXPECT_TIMEOUT, null);

            // Act.
            _ctrlFirst.SendData(NODE_ID_2, Notify(SEVERITY, S2_MESSAGE_ENCAPSULATION), TXO);
            var expectRes = (ExpectDataResult)expectToken.WaitCompletedSignal();

            // Assert.
            Assert.IsTrue(expectRes);
            Assert.IsTrue(expectRes.Command.SequenceEqual(S2_MESSAGE_ENCAPSULATION));
        }

        [Test]
        public void SubstituteActionInternal_NoCommandData_LeavesActionUnchanged()
        {
            // Arrange: the SecurityManager answers an S2 MOS extension with an MPAN-only action.
            var network = new NetworkViewPoint();
            var action = new SendDataOperation(network, NODE_ID_2, null, TXO) { SubstituteSettings = Settings(SEVERITY) };

            // Act.
            var result = new WakeOnCriticalMessageManager(network).SubstituteActionInternal(action);

            // Assert.
            Assert.IsNull(result);
            Assert.IsNull(action.Data);
        }

        internal static SubstituteSettings Settings(byte severity)
        {
            return new SubstituteSettings { WakeOnCriticalMessageSeverity = severity };
        }

        internal static byte[] Notify(byte severity, byte[] payload)
        {
            return new COMMAND_CLASS_WAKE_ON_CRITICAL_MESSAGE.WAKE_ON_CRITICAL_MESSAGE_NOTIFY()
            {
                properties1 = severity,
                payloadLength = (byte)payload.Length,
                encapsulatedPayload = payload.ToList()
            };
        }
    }
}
