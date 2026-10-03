// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title PhoenixOracleRegistry
 * @notice On-chain registry for Phoenix Zero sequencer health signals.
 *         Stores the latest P99 RTT and revert ratio for Base chain,
 *         published by the authorized oracle node.
 */
contract PhoenixOracleRegistry {

    address public owner;
    address public oracle;

    struct SequencerSnapshot {
        uint32  base_p99_ms;
        uint16  revert_ratio_bps;
        uint8   risk_level;         // 0=SAFE 1=ELEVATED 2=HIGH 3=STALL
        uint32  timestamp;
        uint64  block_number;
    }

    SequencerSnapshot public latest;
    uint256 public updateCount;

    event SnapshotPublished(
        uint32  base_p99_ms,
        uint16  revert_ratio_bps,
        uint8   risk_level,
        uint32  timestamp,
        uint64  block_number
    );

    event OracleUpdated(address indexed previous, address indexed next);

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    modifier onlyOracle() {
        require(msg.sender == oracle || msg.sender == owner, "not oracle");
        _;
    }

    constructor(address _oracle) {
        owner  = msg.sender;
        oracle = _oracle;
    }

    function publish(
        uint32 p99_ms,
        uint16 revert_bps,
        uint8  risk,
        uint32 ts,
        uint64 blockNum
    ) external onlyOracle {
        require(risk <= 3, "invalid risk level");
        latest = SequencerSnapshot(p99_ms, revert_bps, risk, ts, blockNum);
        updateCount++;
        emit SnapshotPublished(p99_ms, revert_bps, risk, ts, blockNum);
    }

    function isSafe() external view returns (bool) {
        return latest.risk_level == 0;
    }

    function riskLabel() external view returns (string memory) {
        if (latest.risk_level == 0) return "SAFE";
        if (latest.risk_level == 1) return "ELEVATED";
        if (latest.risk_level == 2) return "HIGH";
        return "STALL";
    }

    function setOracle(address _oracle) external onlyOwner {
        emit OracleUpdated(oracle, _oracle);
        oracle = _oracle;
    }

    function transferOwnership(address _owner) external onlyOwner {
        owner = _owner;
    }
}
