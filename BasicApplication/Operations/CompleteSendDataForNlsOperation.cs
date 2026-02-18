/// SPDX-License-Identifier: BSD-3-Clause
/// SPDX-FileCopyrightText: Z-Wave Alliance https://z-wavealliance.org
using System;
using ZWave.Enums;
using ZWave.Devices;
using ZWave.Layers;
using Utils;

namespace ZWave.BasicApplication.Operations
{
    /// <summary>
    /// Runs on the session thread to complete the SendDataOperation that matches the given node and payload
    /// when the chip used the NLS path (0x6C → 0xAC). The chip does not send a 0x13 transmit report for that path,
    /// so the host must complete the original SendDataOperation when 0xAC completes.
    /// </summary>
    public class CompleteSendDataForNlsOperation : ActionBase
    {
        private readonly ISessionClient _sessionClient;
        private readonly Action<ActionBase> _executeAsync;
        private readonly NodeTag _nodeId;
        private readonly byte[] _payload;
        private readonly byte _txStatus;
        private readonly SendDataResult _txReport;

        public CompleteSendDataForNlsOperation(
            ISessionClient sessionClient,
            Action<ActionBase> executeAsync,
            NodeTag nodeId,
            byte[] payload,
            byte txStatus,
            SendDataResult txReport)
            : base(false)
        {
            _sessionClient = sessionClient ?? throw new ArgumentNullException(nameof(sessionClient));
            _executeAsync = executeAsync ?? throw new ArgumentNullException(nameof(executeAsync));
            _nodeId = nodeId;
            _payload = payload;
            _txStatus = txStatus;
            _txReport = txReport;
        }

        protected override void CreateWorkflow()
        {
            ActionUnits.Add(new StartActionUnit(OnStart, 0));
        }

        protected override void CreateInstance()
        {
        }

        private void OnStart(StartActionUnit sau)
        {
            if (_sessionClient.RunningActions == null)
            {
                SetStateCompleted(sau);
                return;
            }
            SendDataOperation toComplete = null;
            foreach (var kv in _sessionClient.RunningActions)
            {
                if (kv.Value is SendDataOperation sdo
                    && sdo.DstNode.Id == _nodeId.Id
                    && PayloadEquals(sdo.Data, _payload))
                {
                    toComplete = sdo;
                    break;
                }
            }
            if (toComplete != null)
            {
                toComplete.SpecificResult.TransmitStatus = (TransmitStatuses)_txStatus;
                if (_txReport != null)
                {
                    toComplete.SpecificResult.CopyFrom(_txReport);
                }
                toComplete.SetCompleted();
                _executeAsync(toComplete);
                "CompleteSendDataForNls: completed SendDataOperation (Id={0}) for nodeId={1} status=0x{2:X2}"
                    ._DLOG(toComplete.Id, _nodeId.Id, _txStatus);
            }
            SetStateCompleted(sau);
        }

        private static bool PayloadEquals(byte[] a, byte[] b)
        {
            if (a == null || b == null || a.Length != b.Length) return false;
            for (int i = 0; i < a.Length; i++)
                if (a[i] != b[i]) return false;
            return true;
        }
    }
}
