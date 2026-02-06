/// SPDX-License-Identifier: BSD-3-Clause
/// SPDX-FileCopyrightText: Z-Wave Alliance https://z-wavealliance.org
using System.Collections.Generic;
using System.Linq;
using ZWave.BasicApplication.Enums;
using ZWave.Devices;
using ZWave.Enums;

namespace ZWave.BasicApplication.Operations
{
    /// <summary>
    /// Gets the list of NLS nodes (Get NLS Nodes (0xC0)).
    /// HOST->ZW: REQ | 0xC0 | nls_nodes_list_start_offset
    /// ZW->HOST: RES | 0xC0 | more_nodes | start_offset | list_length | list[]
    /// </summary>
    public class SerialApiGetNlsNodesOperation : ApiOperation
    {
        internal int TimeoutMs { get; set; }

        public SerialApiGetNlsNodesOperation(NetworkViewPoint network)
            : base(true, CommandTypes.CmdSerialApiGetNlsNodes, false)
        {
            _network = network;
            TimeoutMs = 200;
        }

        protected ApiMessage message;
        private ApiHandler handler;
        private byte offset = 0;
        private readonly HashSet<ushort> includedNodeIds = new HashSet<ushort>();

        protected override void CreateWorkflow()
        {
            ActionUnits.Add(new StartActionUnit(null, TimeoutMs, message));
            ActionUnits.Add(new DataReceivedUnit(handler, OnReceived));
        }

        protected override void CreateInstance()
        {
            message = new ApiMessage(SerialApiCommands[0], offset);
            handler = new ApiHandler(FrameTypes.Response, SerialApiCommands[0]);
        }

        protected void OnReceived(DataReceivedUnit ou)
        {
            var payload = ou.DataFrame?.Payload;
            if (payload == null || payload.Length < 3)
            {
                SetStateFailed(ou);
                return;
            }
            bool moreNodes = (payload[0] & 0x80) != 0;
            byte responseOffset = payload[1];
            int listLength = payload[2];
            int availableLength = payload.Length - 3;
            if (listLength > availableLength)
            {
                listLength = availableLength;
            }
            ParseResponse(payload, responseOffset, listLength);
            SpecificResult.MoreNodes = moreNodes;
            SpecificResult.LastOffset = responseOffset;
            if (moreNodes)
            {
                offset = (byte)(responseOffset + 1);
                message = new ApiMessage(SerialApiCommands[0], offset);
                ou.SetNextActionItems(message);
                return;
            }
            SpecificResult.IncludedNodes = includedNodeIds.Select(id => new NodeTag(id)).ToArray();
            SetStateCompleted(ou);
        }

        private void ParseResponse(byte[] payload, byte responseOffset, int listLength)
        {
            int offsetBase = 128 * 8 * responseOffset;
            for (int j = 0; j < listLength; j++)
            {
                byte availabilityMask = payload[3 + j];
                for (int bit = 0; bit < 8; bit++)
                {
                    if ((availabilityMask & (1 << bit)) == 0)
                    {
                        continue;
                    }
                    int nodeId;
                    if (j <= 28)
                    {
                        nodeId = 1 + (8 * j) + bit + offsetBase;
                    }
                    else
                    {
                        nodeId = 24 + (8 * j) + bit + offsetBase;
                    }
                    if (!IsValidNlsNodeId(nodeId))
                    {
                        continue;
                    }
                    includedNodeIds.Add((ushort)nodeId);
                }
            }
        }

        private static bool IsValidNlsNodeId(int nodeId)
        {
            if (nodeId <= 0)
            {
                return false;
            }
            if (nodeId >= 233 && nodeId <= 255)
            {
                return false;
            }
            if (nodeId >= 4002 && nodeId <= 4005)
            {
                return false;
            }
            if (nodeId > ushort.MaxValue)
            {
                return false;
            }
            return true;
        }

        public SerialApiGetNlsNodesResult SpecificResult => (SerialApiGetNlsNodesResult)Result;

        protected override ActionResult CreateOperationResult()
        {
            return new SerialApiGetNlsNodesResult();
        }
    }

    public class SerialApiGetNlsNodesResult : ActionResult
    {
        public NodeTag[] IncludedNodes { get; set; }
        public byte LastOffset { get; set; }
        public bool MoreNodes { get; set; }
    }
}
