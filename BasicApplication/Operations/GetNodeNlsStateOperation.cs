/// SPDX-License-Identifier: BSD-3-Clause
/// SPDX-FileCopyrightText: Z-Wave Alliance https://z-wavealliance.org
using ZWave.BasicApplication.Enums;
using ZWave.Devices;

namespace ZWave.BasicApplication.Operations
{
    /// <summary>
    /// Gets NLS state for a node (Get Node NLS State (0x6B)).
    /// HOST->ZW: REQ | 0x6B | node_id
    /// ZW->HOST: RES | 0x6B | nls_support | nls_state
    /// </summary>
    public class GetNodeNlsStateOperation : RequestApiOperation
    {
        public NodeTag NodeId { get; set; }

        public GetNodeNlsStateOperation(NetworkViewPoint network, NodeTag nodeId)
            : base(CommandTypes.CmdZWaveGetNodeNlsState)
        {
            _network = network;
            NodeId = nodeId;
        }

        protected override byte[] CreateInputParameters()
        {
            if (_network != null && _network.IsNodeIdBaseTypeLR)
            {
                return new byte[] { (byte)(NodeId.Id >> 8), (byte)NodeId.Id };
            }
            return new byte[] { (byte)NodeId.Id };
        }

        protected override void SetStateCompleted(IActionUnit ou)
        {
            var payload = (ou as DataReceivedUnit)?.DataFrame?.Payload;
            if (payload != null)
            {
                if (payload.Length > 0)
                {
                    SpecificResult.NlsSupport = payload[0];
                }
                if (payload.Length > 1)
                {
                    SpecificResult.NlsState = payload[1];
                }
            }
            base.SetStateCompleted(ou);
        }

        public GetNodeNlsStateResult SpecificResult => (GetNodeNlsStateResult)Result;

        protected override ActionResult CreateOperationResult()
        {
            return new GetNodeNlsStateResult();
        }
    }

    public class GetNodeNlsStateResult : ActionResult
    {
        public byte NlsSupport { get; set; }
        public byte NlsState { get; set; }
        public bool IsNlsSupported => NlsSupport == 0x01;
        public bool IsNlsEnabled => NlsState == 0x01;
    }
}
