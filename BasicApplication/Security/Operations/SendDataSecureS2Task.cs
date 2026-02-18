/// SPDX-License-Identifier: BSD-3-Clause
/// SPDX-FileCopyrightText: Silicon Laboratories Inc. https://www.silabs.com
using System;
using System.Linq;
using System.Collections.Generic;
using System.Threading;
using Utils;
using ZWave.BasicApplication.Enums;
using ZWave.BasicApplication.Security;
using ZWave.CommandClasses;
using ZWave.Enums;
using ZWave.Security;
using ZWave.Devices;

namespace ZWave.BasicApplication.Operations
{
    public class SendDataSecureS2Task : ApiOperation
    {
        #region Timeouts
        /// <summary>
        /// Nonce Request Timer
        /// </summary>
        public static int NONCE_REQUEST_INCLUSION_TIMER = 10000;
        /// <summary>
        /// Nonce Request Timer
        /// </summary>
        public static int NONCE_REQUEST_TIMER = 10000;
        #endregion

        protected TransmitOptions TxOptions { get; set; }
        internal byte[] CommandToSecureSend { get; private set; }
        internal NodeTag Node { get; private set; }
        internal NodeTag? TestNode { get; set; }
        private SecurityManagerInfo _securityManagerInfo;
        private SecurityS2CryptoProvider _securityS2CryptoProvider;
        private MpanTable _mpanTable;
        private SpanTable _spanTable;
        private readonly SinglecastKey _sckey;
        private RequestDataOperation _requestNonce;
        private SendDataOperation _sendEncData;
        private ApiHandler _handlerCommandComplete;
        private ApiHandler _handlerCommandCompleteBridge;
        private InvariantPeerNodeId _peerNodeId;
        private readonly ISecurityTestSettingsService _securityTestSettingsService;
        public Action SubstituteCallback { get; set; }
        public Extensions ExtensionsToAdd { get; set; }
        public SubstituteSettings SubstituteSettingsForRetransmission { get; set; }
        internal SendDataSecureS2Task(NetworkViewPoint network, SecurityManagerInfo securityManagerInfo,
            SecurityS2CryptoProvider securityS2CryptoProvider, SinglecastKey sckey, SpanTable spanTable, MpanTable mpanTable,
            NodeTag node,
            byte[] data,
            TransmitOptions txOptions)
            : base(false, null, false)
        {
            _network = network;
            _securityManagerInfo = securityManagerInfo;
            _securityS2CryptoProvider = securityS2CryptoProvider;
            _mpanTable = mpanTable;
            _spanTable = spanTable;
            _sckey = sckey;
            SubstituteSettings.SetFlag(SubstituteFlags.DenySecurity);
            CommandToSecureSend = data;
            Node = node;
            _peerNodeId = new InvariantPeerNodeId(_securityManagerInfo.Network.NodeTag, Node);
            TxOptions = txOptions;
            _securityTestSettingsService = new SecurityTestSettingsService(_securityManagerInfo, false);
            // So COMMAND_COMPLETE from the node is matched by this task before other actions (e.g. TransferProtocolCc, ListenData).
            IsFirstPriority = true;
        }

        protected override void CreateWorkflow()
        {
            // Complete when COMMAND_COMPLETE (0x01 0x07) is received from the node (e.g. NLS Find Nodes in Range response).
            // Match both regular ACH (0x04) and Bridge (0xA8); NLS returns S2-encapsulated response as bridge.
            ActionUnits.Add(new DataReceivedUnit(_handlerCommandComplete, OnCommandComplete));
            ActionUnits.Add(new DataReceivedUnit(_handlerCommandCompleteBridge, OnCommandComplete));
            ActionUnits.Add(new StartActionUnit(OnStart, 0, _requestNonce));
            ActionUnits.Add(new ActionCompletedUnit(_requestNonce, OnNonceReport, _sendEncData));
            ActionUnits.Add(new ActionCompletedUnit(_sendEncData, OnSendEncData));
        }

        protected override void CreateInstance()
        {
            _spanTable.UpdateTxSequenceNumber(_peerNodeId);
            _requestNonce = new RequestDataOperation(_network, NodeTag.Empty,
                Node,
                new COMMAND_CLASS_SECURITY_2.SECURITY_2_NONCE_GET()
                {
                    sequenceNumber = _spanTable.GetTxSequenceNumber(_peerNodeId)
                },
                TxOptions,
                new[]
                {
                    new ByteIndex( COMMAND_CLASS_SECURITY_2.ID),
                    new ByteIndex( COMMAND_CLASS_SECURITY_2.SECURITY_2_NONCE_REPORT.ID),
                    ByteIndex.AnyValue,
                    new ByteIndex(0x01, 0x01),
                    ByteIndex.AnyValue,
                    ByteIndex.AnyValue,
                    ByteIndex.AnyValue,
                    ByteIndex.AnyValue,
                    ByteIndex.AnyValue,
                    ByteIndex.AnyValue,
                    ByteIndex.AnyValue,
                    ByteIndex.AnyValue,
                    ByteIndex.AnyValue,
                    ByteIndex.AnyValue,
                    ByteIndex.AnyValue,
                    ByteIndex.AnyValue,
                    ByteIndex.AnyValue,
                    ByteIndex.AnyValue,
                    ByteIndex.AnyValue,
                    ByteIndex.AnyValue
                },
                NONCE_REQUEST_TIMER);
            _requestNonce.SubstituteSettings.SetFlag(SubstituteFlags.DenySecurity);
            _requestNonce.IsHandler = true;
            _securityManagerInfo.InitializingNodeId = Node;

            _sendEncData = new SendDataOperation(_network, TestNode ?? Node, null, TxOptions);
            _sendEncData.SubstituteSettings.SetFlag(SubstituteFlags.DenySecurity);

            // Match ACH COMMAND_COMPLETE from the node (e.g. NLS Find Nodes in Range response)
            _handlerCommandComplete = new ApiHandler(FrameTypes.Request, CommandTypes.CmdApplicationCommandHandler);
            _handlerCommandComplete.AddConditions(
                ByteIndex.AnyValue,
                Node.Id > 0 && Node.Id < 255 ? new ByteIndex((byte)Node.Id) : ByteIndex.AnyValue,
                ByteIndex.AnyValue,
                new ByteIndex(ZWave.CommandClasses.ZWAVE_CMD_CLASS.ID),
                new ByteIndex(ZWave.CommandClasses.ZWAVE_CMD_CLASS.COMMAND_COMPLETE.ID));
            if (_network.IsNodeIdBaseTypeLR)
            {
                _handlerCommandComplete = new ApiHandler(FrameTypes.Request, CommandTypes.CmdApplicationCommandHandler);
                _handlerCommandComplete.AddConditions(
                    ByteIndex.AnyValue,
                    Node.Id > 0 && Node.Id != 0xFF ? new ByteIndex((byte)(Node.Id >> 8)) : ByteIndex.AnyValue,
                    Node.Id > 0 && Node.Id != 0xFF ? new ByteIndex((byte)Node.Id) : ByteIndex.AnyValue,
                    ByteIndex.AnyValue,
                    new ByteIndex(ZWave.CommandClasses.ZWAVE_CMD_CLASS.ID),
                    new ByteIndex(ZWave.CommandClasses.ZWAVE_CMD_CLASS.COMMAND_COMPLETE.ID));
            }

            // Bridge (0xA8): NLS returns S2-encapsulated COMMAND_COMPLETE as bridge; decrypted frame keeps 0xA8 format.
            _handlerCommandCompleteBridge = new ApiHandler(FrameTypes.Request, CommandTypes.CmdApplicationCommandHandler_Bridge);
            _handlerCommandCompleteBridge.AddConditions(
                ByteIndex.AnyValue,
                ByteIndex.AnyValue,
                Node.Id > 0 && Node.Id < 255 ? new ByteIndex((byte)Node.Id) : ByteIndex.AnyValue,
                ByteIndex.AnyValue,
                new ByteIndex(ZWave.CommandClasses.ZWAVE_CMD_CLASS.ID),
                new ByteIndex(ZWave.CommandClasses.ZWAVE_CMD_CLASS.COMMAND_COMPLETE.ID));
            if (_network.IsNodeIdBaseTypeLR)
            {
                _handlerCommandCompleteBridge = new ApiHandler(FrameTypes.Request, CommandTypes.CmdApplicationCommandHandler_Bridge);
                _handlerCommandCompleteBridge.AddConditions(
                    ByteIndex.AnyValue,
                    ByteIndex.AnyValue,
                    ByteIndex.AnyValue,
                    Node.Id > 0 && Node.Id != 0xFF ? new ByteIndex((byte)(Node.Id >> 8)) : ByteIndex.AnyValue,
                    Node.Id > 0 && Node.Id != 0xFF ? new ByteIndex((byte)Node.Id) : ByteIndex.AnyValue,
                    ByteIndex.AnyValue,
                    new ByteIndex(ZWave.CommandClasses.ZWAVE_CMD_CLASS.ID),
                    new ByteIndex(ZWave.CommandClasses.ZWAVE_CMD_CLASS.COMMAND_COMPLETE.ID));
            }
        }

        private void OnStart(StartActionUnit taskUnit)
        {
            if (_securityManagerInfo.IsInclusion)
            {
                taskUnit.AddNextActionItems(new TimeInterval(0, _requestNonce.Id, DefaultTimeouts.SECURITY_S2_NONCE_REQUEST_INCLUSION_TIMEOUT));
            }
            if (_securityManagerInfo.RetransmissionTableS2.TryRemove(_peerNodeId, out RetransmissionRecord rrec))
            {
            }

            #region NonceGet
            _securityTestSettingsService.ActivateTestPropertiesForFrame(SecurityS2TestFrames.NonceGet, _requestNonce);
            #endregion
        }

        private void OnNonceReport(ActionCompletedUnit ou)
        {
            AddTraceLogItems(_requestNonce.SpecificResult.TraceLog);
            SpecificResult.TransmitStatus = (_requestNonce.Result as TransmitResult).TransmitStatus;
            if (_requestNonce.Result)
            {
                COMMAND_CLASS_SECURITY_2.SECURITY_2_NONCE_REPORT cmd = _requestNonce.SpecificResult.Command;
                "NONCE REPORT {0}"._DLOG(_requestNonce.SpecificResult.Command.GetHex());
                if (cmd.receiversEntropyInput != null && cmd.receiversEntropyInput.Count == 16 && cmd.properties1.sos == 1 /* SOS flag */)
                {
                    _spanTable.AddOrReplace(_peerNodeId,
                        cmd.receiversEntropyInput.ToArray(), _spanTable.GetTxSequenceNumber(_peerNodeId), cmd.sequenceNumber);
                    _securityManagerInfo.InitializingNodeId = NodeTag.Empty;
                    if (cmd.properties1.mos == 1)
                    {
                        var groupId = _securityS2CryptoProvider.LastSentMulticastGroupId;
                        var nodeGroupId = new NodeGroupId(_securityManagerInfo.Network.NodeTag, groupId);
                        if (groupId != 0 && _mpanTable.CheckMpanExists(nodeGroupId))
                        {
                            if (ExtensionsToAdd == null)
                            {
                                ExtensionsToAdd = new Extensions();
                            }
                            ExtensionsToAdd.AddMpanExtension(
                                _mpanTable.GetContainer(nodeGroupId).MpanState,
                                groupId
                                );
                        };
                    }

                    var cryptedData = _securityS2CryptoProvider.EncryptSinglecastCommand(_sckey, _spanTable, _securityManagerInfo.Network.NodeTag, Node, _securityManagerInfo.Network.HomeId, CommandToSecureSend, ExtensionsToAdd, SubstituteSettingsForRetransmission);
                    if (cryptedData != null)
                    {
                        SubstituteCallback?.Invoke();
                        _securityManagerInfo.LastSendDataBuffer = cryptedData;
                        _sendEncData.Data = cryptedData;

                        #region MessageEncapsulation
                        _sendEncData.Data = _securityManagerInfo.TestOverrideMessageEncapsulation(_sckey, _spanTable, _securityS2CryptoProvider, SubstituteSettings, Node, CommandToSecureSend, _peerNodeId, ExtensionsToAdd, cryptedData, _sendEncData.Data);
                        #endregion
                    }
                    else
                    {
                        "No Data to Send"._DLOG();
                        SpecificResult.TxSubstituteStatus = SubstituteStatuses.Failed;
                        SetStateFailed(ou);
                    }
                }
                else
                {
                    "Invalid Nonce {0}"._DLOG(_requestNonce.SpecificResult.Command.GetHex());
                }
            }
            else
            {
                SpecificResult.TxSubstituteStatus = SubstituteStatuses.Failed;
                SetStateFailed(ou);
            }
        }

        private void OnCommandComplete(DataReceivedUnit ou)
        {
            "S2 send: COMMAND_COMPLETE received from node {0}"._DLOG(Node.Id);
            SpecificResult.TxSubstituteStatus = SubstituteStatuses.Done;
            SpecificResult.TransmitStatus = TransmitStatuses.CompleteOk;
            SetStateCompleted(ou);
        }

        private void OnSendEncData(ActionCompletedUnit ou)
        {
            AddTraceLogItems(_sendEncData.SpecificResult.TraceLog);
            SpecificResult.CopyFrom(_requestNonce.Result as SendDataResult);
            SpecificResult.AggregateWith(_sendEncData.Result as SendDataResult);
            if (_sendEncData.Result.State == ActionStates.Completed)
            {
                SpecificResult.TxSubstituteStatus = SubstituteStatuses.Done;
                SetStateCompleted(ou);
            }
            else
            {
                SpecificResult.TxSubstituteStatus = SubstituteStatuses.Failed;
                SetStateFailed(ou);
            }
        }

        public SendDataResult SpecificResult
        {
            get { return (SendDataResult)Result; }
        }

        protected override ActionResult CreateOperationResult()
        {
            return new SendDataResult();
        }

    }
}
