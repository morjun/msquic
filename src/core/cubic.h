/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#pragma once

typedef enum QUIC_CUBIC_HYSTART_STATE {
    HYSTART_NOT_STARTED = 0,
    HYSTART_ACTIVE = 1,
    HYSTART_DONE = 2
} QUIC_CUBIC_HYSTART_STATE;

typedef struct QUIC_CONGESTION_CONTROL_CUBIC {

    //
    // TRUE if we have had at least one congestion event.
    // If TRUE, RecoverySentPacketNumber is valid.
    //
    BOOLEAN HasHadCongestionEvent : 1;

    //
    // This flag indicates a congestion event occurred and CC is attempting
    // to recover from it.
    //
    BOOLEAN IsInRecovery : 1;

    //
    // This flag indicates a persistent congestion event occurred and CC is
    // attempting to recover from it.
    //
    BOOLEAN IsInPersistentCongestion : 1;

    //
    // TRUE if there has been at least one ACK.
    //
    BOOLEAN TimeOfLastAckValid : 1;

    //
    // The size of the initial congestion window, in packets.
    //
    uint32_t InitialWindowPackets;

    //
    // Minimum time without any sends before the congestion window is reset.
    //
    uint32_t SendIdleTimeoutMs;

    uint32_t CongestionWindow; // bytes
    uint32_t PrevCongestionWindow; // bytes
    uint32_t SlowStartThreshold; // bytes
    uint32_t PrevSlowStartThreshold; // bytes
    uint32_t AimdWindow; // bytes
    uint32_t PrevAimdWindow; // bytes
    uint32_t AimdAccumulator; // bytes

    //
    // The number of bytes considered to be still in the network.
    //
    // The client of this module should send packets until BytesInFlight becomes
    // larger than CongestionWindow (see QuicCongestionControlCanSend). This
    // means BytesInFlight can become larger than CongestionWindow by up to one
    // packet's worth of bytes, plus exemptions (see Exemptions variable).
    //
    uint32_t BytesInFlight;
    uint32_t BytesInFlightMax;

    //
    // The leftover send allowance from a previous send. Only used when pacing.
    //
    uint32_t LastSendAllowance; // bytes

    //
    // A count of packets which can be sent ignoring CongestionWindow.
    // The count is decremented as the packets are sent. BytesInFlight is still
    // incremented for these packets. This is used to send probe packets for
    // loss recovery.
    //
    uint8_t Exemptions;

    uint64_t TimeOfLastAck; // microseconds
    uint64_t TimeOfCongAvoidStart; // microseconds
    uint32_t KCubic; // millisec
    uint32_t PrevKCubic; // millisec
    uint32_t WindowPrior; // bytes (prior_cwnd from rfc8312bis)
    uint32_t PrevWindowPrior; // bytes
    uint32_t WindowMax; // bytes (W_max from rfc8312bis)
    uint32_t PrevWindowMax; // bytes
    uint32_t WindowLastMax; // bytes (W_last_max from rfc8312bis)
    uint32_t PrevWindowLastMax; // bytes

    //
    // HyStart state.
    //
    QUIC_CUBIC_HYSTART_STATE HyStartState;
    uint32_t HyStartAckCount;
    uint64_t MinRttInLastRound; // microseconds
    uint64_t MinRttInCurrentRound; // microseconds
    uint64_t CssBaselineMinRtt; // microseconds
    uint64_t HyStartRoundEnd; // Packet Number
    uint32_t CWndSlowStartGrowthDivisor;
    uint32_t ConservativeSlowStartRounds;

    //
    // This variable tracks the largest packet that was outstanding at the time
    // the last congestion event occurred. An ACK for any packet number greater
    // than this indicates recovery is over.
    //
    uint64_t RecoverySentPacketNumber;

} QUIC_CONGESTION_CONTROL_CUBIC;

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CubicCongestionControlInitialize(
    _In_ QUIC_CONGESTION_CONTROL* Cc,
    _In_ const QUIC_SETTINGS_INTERNAL* Settings
    );


_IRQL_requires_max_(PASSIVE_LEVEL) void QuicLostPacketsForget(
    _In_ QUIC_CONNECTION *Connection);

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicLossDetectionInitialize(
    _Inout_ QUIC_LOSS_DETECTION* LossDetection
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicLossDetectionUninitialize(
    _In_ QUIC_LOSS_DETECTION* LossDetection
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicLossDetectionReset(
    _In_ QUIC_LOSS_DETECTION* LossDetection
    );

//
// Called when a particular key type has been discarded. This removes
// the tracking for all related outstanding packets.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicLossDetectionDiscardPackets(
    _In_ QUIC_LOSS_DETECTION* LossDetection,
    _In_ QUIC_PACKET_KEY_TYPE KeyType
    );

//
// Called when 0-RTT data was rejected.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicLossDetectionOnZeroRttRejected(
    _In_ QUIC_LOSS_DETECTION* LossDetection
    );

//
// Resets the timer based on the current state.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicLossDetectionUpdateTimer(
    _In_ QUIC_LOSS_DETECTION* LossDetection,
    _In_ BOOLEAN ExecuteImmediatelyIfNecessary
    );

//
// Returns the current PTO in microseconds.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
uint64_t
QuicLossDetectionComputeProbeTimeout(
    _In_ QUIC_LOSS_DETECTION* LossDetection,
    _In_ const QUIC_PATH* Path,
    _In_ uint32_t Count
    );

//
// Called when a new packet is sent.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicLossDetectionOnPacketSent(
    _In_ QUIC_LOSS_DETECTION* LossDetection,
    _In_ QUIC_PATH* Path,
    _In_ QUIC_SENT_PACKET_METADATA* SentPacket
    );

//
// Processes a received ACK frame. Returns true if the frame could be
// successfully processed. On failure, 'InvalidFrame' indicates if the frame
// was corrupt or not.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN
QuicLossDetectionProcessAckFrame(
    _In_ QUIC_LOSS_DETECTION* LossDetection,
    _In_ QUIC_PATH* Path,
    _In_ QUIC_RX_PACKET* Packet,
    _In_ QUIC_ENCRYPT_LEVEL EncryptLevel,
    _In_ QUIC_FRAME_TYPE FrameType,
    _In_ uint16_t BufferLength,
    _In_reads_bytes_(BufferLength)
        const uint8_t* const Buffer,
    _Inout_ uint16_t* Offset,
    _Out_ BOOLEAN* InvalidFrame
    );

//
// Called when the loss detection timer fires.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicLossDetectionProcessTimerOperation(
    _In_ QUIC_LOSS_DETECTION* LossDetection
    );
