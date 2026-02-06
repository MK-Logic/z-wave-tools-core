/// SPDX-License-Identifier: BSD-3-Clause
/// SPDX-FileCopyrightText: Z-Wave Alliance https://z-wavealliance.org
using System;
using ZWave.BasicApplication.Enums;
using ZWave.Devices;
using ZWave.Enums;

namespace ZWave.BasicApplication.Operations
{
    /// <summary>
    /// Listens for Request Protocol CC Encryption (0x6C) from the module.
    /// ZW->HOST: REQ | 0x6C (Request Protocol CC Encryption) | destination_node_id | payload_length | payload | protocol_metadata_length | protocol_metadata | use_supervision | session_id
    /// Host shall encrypt the payload (NLS) and send via <see cref="ControllerNodeSendProtocolDataOperation"/>,
    /// then report TX result via <see cref="RequestProtocolCcEncryptionCallbackOperation"/>.
    /// </summary>
    public class RequestProtocolCcEncryptionOperation : ApiOperation
    {
        public Action<RequestProtocolCcEncryptionData> ReceivedCallback { get; set; }

        /// <summary>
        /// Optional. When set and IsNodeIdBaseTypeLR, destination node ID is parsed as 2 bytes (LR).
        /// </summary>
        public NetworkViewPoint NetworkView { get; set; }

        public RequestProtocolCcEncryptionOperation()
            : base(false, CommandTypes.CmdZWaveRequestProtocolCcEncryption, false)
        {
        }

        private ApiHandler _handler;

        protected override void CreateWorkflow()
        {
            ActionUnits.Add(new StartActionUnit(null, 0));
            ActionUnits.Add(new DataReceivedUnit(_handler, OnReceived));
        }

        protected override void CreateInstance()
        {
            _handler = new ApiHandler(FrameTypes.Request, SerialApiCommands[0]);
        }

        private void OnReceived(DataReceivedUnit ou)
        {
            var payload = ou.DataFrame.Payload;
            if (payload == null || payload.Length < 2)
            {
                return;
            }
            int idx = 0;
            ushort destinationNodeId;
            if (NetworkView != null && NetworkView.IsNodeIdBaseTypeLR && payload.Length >= idx + 2)
            {
                destinationNodeId = (ushort)((payload[idx] << 8) | payload[idx + 1]);
                idx += 2;
            }
            else if (payload.Length >= idx + 1)
            {
                destinationNodeId = payload[idx++];
            }
            else
            {
                return;
            }
            if (idx >= payload.Length)
            {
                return;
            }
            byte payloadLength = payload[idx++];
            if (payloadLength > payload.Length - idx)
            {
                return;
            }
            byte[] plainPayload = new byte[payloadLength];
            Buffer.BlockCopy(payload, idx, plainPayload, 0, payloadLength);
            idx += payloadLength;
            if (idx >= payload.Length)
            {
                return;
            }
            byte protocolMetadataLength = payload[idx++];
            if (protocolMetadataLength > payload.Length - idx)
            {
                return;
            }
            byte[] protocolMetadata = new byte[protocolMetadataLength];
            Buffer.BlockCopy(payload, idx, protocolMetadata, 0, protocolMetadataLength);
            idx += protocolMetadataLength;
            if (idx + 2 > payload.Length)
            {
                return;
            }
            byte useSupervision = payload[idx++];
            byte sessionId = payload[idx];
            var data = new RequestProtocolCcEncryptionData(
                new NodeTag(destinationNodeId),
                plainPayload,
                protocolMetadata,
                useSupervision,
                sessionId);
            ReceivedCallback?.Invoke(data);
        }

        protected override ActionResult CreateOperationResult()
        {
            return new ActionResult();
        }
    }

    /// <summary>
    /// Parsed data from Request Protocol CC Encryption (0x6C) Serial API frame.
    /// </summary>
    public class RequestProtocolCcEncryptionData
    {
        public NodeTag DestinationNodeId { get; }
        public byte[] Payload { get; }
        public byte[] ProtocolMetadata { get; }
        public byte UseSupervision { get; }
        public byte SessionId { get; }

        public RequestProtocolCcEncryptionData(NodeTag destinationNodeId, byte[] payload, byte[] protocolMetadata, byte useSupervision, byte sessionId)
        {
            DestinationNodeId = destinationNodeId;
            Payload = payload ?? Array.Empty<byte>();
            ProtocolMetadata = protocolMetadata ?? Array.Empty<byte>();
            UseSupervision = useSupervision;
            SessionId = sessionId;
        }
    }
}
