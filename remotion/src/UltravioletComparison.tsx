import React from 'react';
import {
  AbsoluteFill,
  Easing,
  interpolate,
  Sequence,
  useCurrentFrame,
  useVideoConfig,
} from 'remotion';
import {
  clamp,
  enter,
  GlobalChrome,
  Kicker,
  NoiseGrid,
  ProtocolMark,
  Reveal,
  sceneOpacity,
  Tick,
} from './components';
import {colors, fonts} from './theme';

type Protocol = {
  name: string;
  short: string;
  color: string;
  owner: string;
  anchor: string;
  private: boolean;
  postQuantum: boolean;
  status: string;
  statusTone: 'live' | 'paper' | 'research';
};

const protocols: Protocol[] = [
  {
    name: 'RGB',
    short: 'RGB',
    color: colors.rgb,
    owner: 'UTXO → Schnorr',
    anchor: 'Single-use seal',
    private: false,
    postQuantum: false,
    status: 'MAINNET',
    statusTone: 'live',
  },
  {
    name: 'Taproot Assets',
    short: 'TA',
    color: colors.taproot,
    owner: 'UTXO → Schnorr',
    anchor: 'Taproot output',
    private: false,
    postQuantum: false,
    status: 'MAINNET + LN',
    statusTone: 'live',
  },
  {
    name: 'Shielded CSV',
    short: 'CSV',
    color: colors.shielded,
    owner: 'Notes → Schnorr',
    anchor: '64-byte nullifiers',
    private: true,
    postQuantum: false,
    status: 'PAPER',
    statusTone: 'paper',
  },
  {
    name: 'Ultraviolet',
    short: 'UV',
    color: colors.uv,
    owner: 'Notes → hash preimage',
    anchor: '64-byte records',
    private: true,
    postQuantum: true,
    status: 'RESEARCH / SIGNET',
    statusTone: 'research',
  },
];

const StatusPill: React.FC<{protocol: Protocol}> = ({protocol}) => {
  const tone =
    protocol.statusTone === 'live'
      ? colors.good
      : protocol.statusTone === 'paper'
        ? colors.taproot
        : colors.uvBright;
  return (
    <div
      style={{
        color: tone,
        border: `1px solid ${tone}66`,
        background: `${tone}12`,
        borderRadius: 999,
        padding: '8px 12px',
        fontFamily: fonts.mono,
        fontSize: 14,
        letterSpacing: 1.5,
        fontWeight: 800,
        whiteSpace: 'nowrap',
      }}
    >
      {protocol.status}
    </div>
  );
};

const IntroScene: React.FC = () => {
  const frame = useCurrentFrame();
  const {fps} = useVideoConfig();
  const title = enter(frame, fps, 20, 36);
  const line = interpolate(frame, [40, 130], [0, 1], {
    ...clamp,
    easing: Easing.out(Easing.cubic),
  });
  const marker = interpolate(frame, [75, 165], [0, 1], {
    ...clamp,
    easing: Easing.inOut(Easing.cubic),
  });
  const words = ['R', 'G', 'B'];

  return (
    <AbsoluteFill
      style={{
        opacity: sceneOpacity(frame, 210),
        padding: '150px 120px 120px',
        justifyContent: 'center',
      }}
    >
      <div
        style={{
          position: 'absolute',
          left: 120,
          top: 180,
          width: 6,
          height: 180,
          background: colors.uv,
          boxShadow: `0 0 34px ${colors.uv}`,
          transform: `scaleY(${title})`,
          transformOrigin: 'bottom',
        }}
      />
      <div
        style={{
          marginLeft: 70,
          opacity: title,
          transform: `translateY(${(1 - title) * 45}px)`,
        }}
      >
        <Kicker>Assets on Bitcoin</Kicker>
        <div
          style={{
            color: colors.ink,
            fontFamily: fonts.display,
            fontSize: 112,
            fontWeight: 900,
            lineHeight: 0.96,
            letterSpacing: -6,
            maxWidth: 1250,
          }}
        >
          FOUR ARCHITECTURES.
          <br />
          ONE
          <span style={{color: colors.uv}}> FAMILY TREE.</span>
        </div>
      </div>

      <div
        style={{
          position: 'absolute',
          left: 190,
          right: 190,
          bottom: 180,
          height: 18,
          borderRadius: 30,
          background:
            'linear-gradient(90deg, #6B1225 0%, #FF335F 20%, #FFB657 43%, #38D9B8 64%, #6376FF 78%, #A879FF 88%, rgba(168,121,255,.04) 100%)',
          transform: `scaleX(${line})`,
          transformOrigin: 'left',
          boxShadow: '0 0 32px rgba(168,121,255,.22)',
        }}
      />
      <div
        style={{
          position: 'absolute',
          left: 190,
          right: 190,
          bottom: 117,
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'flex-start',
          fontFamily: fonts.mono,
          color: colors.muted,
          fontSize: 18,
          letterSpacing: 3,
          opacity: line,
        }}
      >
        <div style={{display: 'flex', gap: 135}}>
          {words.map((word) => (
            <span key={word}>{word}</span>
          ))}
        </div>
        <div
          style={{
            color: colors.uvBright,
            fontWeight: 800,
            opacity: marker,
            transform: `translateX(${(1 - marker) * 80}px)`,
          }}
        >
          UV — BEYOND THE VISIBLE BAND
        </div>
      </div>
    </AbsoluteFill>
  );
};

const ProtocolCard: React.FC<{protocol: Protocol; index: number}> = ({
  protocol,
  index,
}) => {
  const frame = useCurrentFrame();
  const {fps} = useVideoConfig();
  const p = enter(frame, fps, 28 + index * 14, 32);
  const pulse = 0.5 + Math.sin((frame - index * 8) / 22) * 0.5;
  return (
    <div
      style={{
        flex: 1,
        minWidth: 0,
        height: 470,
        padding: 28,
        borderRadius: 28,
        border: `1px solid ${protocol.color}55`,
        background: `linear-gradient(145deg, ${protocol.color}16, rgba(17,11,29,.92) 58%)`,
        boxShadow:
          protocol.short === 'UV'
            ? `0 0 ${30 + pulse * 18}px ${protocol.color}28`
            : '0 18px 60px rgba(0,0,0,.22)',
        opacity: p,
        transform: `translateY(${(1 - p) * 75}px) scale(${0.94 + p * 0.06})`,
        position: 'relative',
        overflow: 'hidden',
      }}
    >
      <div
        style={{
          position: 'absolute',
          inset: 0,
          height: 4,
          background: protocol.color,
          boxShadow: `0 0 25px ${protocol.color}`,
        }}
      />
      <div style={{display: 'flex', justifyContent: 'space-between', gap: 12}}>
        <ProtocolMark
          short={protocol.short}
          color={protocol.color}
          active={protocol.short === 'UV'}
        />
        <StatusPill protocol={protocol} />
      </div>
      <div
        style={{
          color: colors.ink,
          fontFamily: fonts.display,
          fontWeight: 900,
          fontSize: protocol.name.length > 12 ? 34 : 42,
          lineHeight: 1.04,
          marginTop: 35,
          minHeight: 84,
        }}
      >
        {protocol.name}
      </div>
      <div
        style={{
          borderTop: `1px solid ${colors.line}`,
          paddingTop: 24,
          display: 'grid',
          gap: 19,
        }}
      >
        <div>
          <div
            style={{
              color: colors.muted,
              fontFamily: fonts.mono,
              fontSize: 14,
              letterSpacing: 2,
              marginBottom: 7,
            }}
          >
            OWNERSHIP
          </div>
          <div
            style={{
              color: colors.ink,
              fontFamily: fonts.body,
              fontSize: 24,
              fontWeight: 700,
            }}
          >
            {protocol.owner}
          </div>
        </div>
        <div>
          <div
            style={{
              color: colors.muted,
              fontFamily: fonts.mono,
              fontSize: 14,
              letterSpacing: 2,
              marginBottom: 7,
            }}
          >
            BITCOIN ANCHOR
          </div>
          <div
            style={{
              color: protocol.color,
              fontFamily: fonts.body,
              fontSize: 22,
              fontWeight: 700,
            }}
          >
            {protocol.anchor}
          </div>
        </div>
      </div>
    </div>
  );
};

const FieldScene: React.FC = () => {
  const frame = useCurrentFrame();
  return (
    <AbsoluteFill
      style={{
        opacity: sceneOpacity(frame, 270),
        padding: '135px 80px 95px',
      }}
    >
      <Reveal delay={3}>
        <Kicker>The field</Kicker>
        <div
          style={{
            color: colors.ink,
            fontFamily: fonts.display,
            fontSize: 66,
            fontWeight: 900,
            letterSpacing: -3,
          }}
        >
          COUSINS, NOT STRANGERS.
        </div>
      </Reveal>
      <div
        style={{
          display: 'flex',
          gap: 24,
          marginTop: 45,
        }}
      >
        {protocols.map((protocol, index) => (
          <ProtocolCard key={protocol.name} protocol={protocol} index={index} />
        ))}
      </div>
    </AbsoluteFill>
  );
};

const UtxoStack: React.FC<{color: string; label: string; delay: number}> = ({
  color,
  label,
  delay,
}) => {
  const frame = useCurrentFrame();
  const {fps} = useVideoConfig();
  const p = enter(frame, fps, delay, 28);
  return (
    <div
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: 17,
        opacity: p,
        transform: `translateX(${(1 - p) * -35}px)`,
      }}
    >
      <div
        style={{
          width: 90,
          height: 66,
          borderRadius: 13,
          border: `2px solid ${colors.bitcoin}`,
          background: `${colors.bitcoin}14`,
          position: 'relative',
          display: 'grid',
          placeItems: 'center',
          color: colors.bitcoin,
          fontFamily: fonts.display,
          fontSize: 23,
        }}
      >
        UTXO
        <div
          style={{
            position: 'absolute',
            right: -15,
            width: 15,
            height: 2,
            background: colors.bitcoin,
          }}
        />
      </div>
      <div
        style={{
          width: 54,
          height: 54,
          border: `2px solid ${color}`,
          borderRadius: '50%',
          background: `${color}16`,
          boxShadow: `0 0 24px ${color}28`,
        }}
      />
      <div
        style={{
          color: colors.ink,
          fontFamily: fonts.body,
          fontSize: 25,
          fontWeight: 750,
        }}
      >
        {label}
      </div>
    </div>
  );
};

const RecordStream: React.FC<{delay: number}> = ({delay}) => {
  const frame = useCurrentFrame();
  const {fps} = useVideoConfig();
  const p = enter(frame, fps, delay, 30);
  return (
    <div style={{opacity: p}}>
      <div style={{display: 'flex', alignItems: 'center', gap: 10}}>
        {Array.from({length: 9}, (_, index) => {
          const on = interpolate(
            frame,
            [delay + 12 + index * 4, delay + 21 + index * 4],
            [0.18, 1],
            clamp,
          );
          return (
            <div
              key={index}
              style={{
                width: index === 8 ? 118 : 46,
                height: 48,
                borderRadius: 9,
                border: `1px solid ${
                  index === 8 ? colors.uv : colors.line
                }`,
                background:
                  index === 8 ? `${colors.uv}20` : colors.panel2,
                opacity: on,
                boxShadow:
                  index === 8 ? `0 0 26px ${colors.uv}40` : 'none',
              }}
            />
          );
        })}
      </div>
      <div
        style={{
          color: colors.muted,
          fontFamily: fonts.mono,
          fontSize: 16,
          letterSpacing: 2,
          marginTop: 14,
        }}
      >
        BITCOIN ORDERS OPAQUE ≈64-BYTE APPLICATION RECORDS
      </div>
    </div>
  );
};

const OwnershipScene: React.FC = () => {
  const frame = useCurrentFrame();
  return (
    <AbsoluteFill
      style={{
        opacity: sceneOpacity(frame, 300),
        padding: '140px 90px 100px',
      }}
    >
      <Reveal>
        <Kicker>01 / Ownership</Kicker>
        <div
          style={{
            fontFamily: fonts.display,
            fontWeight: 900,
            fontSize: 72,
            color: colors.ink,
            letterSpacing: -3,
          }}
        >
          WHAT ACTUALLY OWNS THE ASSET?
        </div>
      </Reveal>

      <div
        style={{
          display: 'grid',
          gridTemplateColumns: '1fr 1fr',
          gap: 28,
          marginTop: 45,
          height: 600,
        }}
      >
        <Reveal delay={18} y={55}>
          <div
            style={{
              height: '100%',
              padding: '34px 38px',
              borderRadius: 28,
              border: `1px solid ${colors.taproot}55`,
              background:
                'linear-gradient(145deg, rgba(255,182,87,.10), rgba(17,11,29,.92) 60%)',
            }}
          >
            <div
              style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
              }}
            >
              <div>
                <div
                  style={{
                    color: colors.taproot,
                    fontFamily: fonts.mono,
                    fontWeight: 800,
                    fontSize: 18,
                    letterSpacing: 3,
                  }}
                >
                  RGB + TAPROOT ASSETS
                </div>
                <div
                  style={{
                    color: colors.ink,
                    fontFamily: fonts.display,
                    fontSize: 40,
                    fontWeight: 900,
                    marginTop: 10,
                  }}
                >
                  UTXO-BOUND
                </div>
              </div>
              <div
                style={{
                  color: colors.bitcoin,
                  fontFamily: fonts.display,
                  fontSize: 56,
                }}
              >
                ₿
              </div>
            </div>
            <div style={{display: 'grid', gap: 25, marginTop: 45}}>
              <UtxoStack color={colors.rgb} label="RGB single-use seal" delay={35} />
              <UtxoStack
                color={colors.taproot}
                label="Taproot asset commitment"
                delay={48}
              />
            </div>
            <div
              style={{
                borderTop: `1px solid ${colors.line}`,
                marginTop: 40,
                paddingTop: 25,
              }}
            >
              <Tick state="yes" label="Needs a Bitcoin UTXO to receive" />
              <div style={{height: 16}} />
              <Tick state="no" label="Schnorr ownership is not post-quantum" />
            </div>
          </div>
        </Reveal>

        <Reveal delay={30} y={55}>
          <div
            style={{
              height: '100%',
              padding: '34px 38px',
              borderRadius: 28,
              border: `1px solid ${colors.uv}80`,
              background:
                'linear-gradient(145deg, rgba(168,121,255,.15), rgba(17,11,29,.94) 60%)',
              boxShadow: `0 0 50px ${colors.uv}1F`,
            }}
          >
            <div
              style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
              }}
            >
              <div>
                <div
                  style={{
                    color: colors.uvBright,
                    fontFamily: fonts.mono,
                    fontWeight: 800,
                    fontSize: 18,
                    letterSpacing: 3,
                  }}
                >
                  SHIELDED CSV + ULTRAVIOLET
                </div>
                <div
                  style={{
                    color: colors.ink,
                    fontFamily: fonts.display,
                    fontSize: 40,
                    fontWeight: 900,
                    marginTop: 10,
                  }}
                >
                  CLIENT-SIDE NOTES
                </div>
              </div>
              <ProtocolMark
                short="UV"
                color={colors.uv}
                size={80}
                active
              />
            </div>
            <div style={{marginTop: 48}}>
              <RecordStream delay={50} />
            </div>
            <div
              style={{
                borderTop: `1px solid ${colors.line}`,
                marginTop: 40,
                paddingTop: 25,
              }}
            >
              <Tick
                state="no"
                label="Requires a Bitcoin UTXO to receive"
              />
              <div style={{height: 16}} />
              <Tick
                state="yes"
                label="UV proves a hash preimage—no spend signature"
              />
            </div>
          </div>
        </Reveal>
      </div>
    </AbsoluteFill>
  );
};

const HistoryPacket: React.FC<{
  protocol: Protocol;
  index: number;
}> = ({protocol, index}) => {
  const frame = useCurrentFrame();
  const {fps} = useVideoConfig();
  const p = enter(frame, fps, 30 + index * 18, 30);
  const shield = protocol.private;
  const travel = interpolate(
    frame,
    [62 + index * 13, 135 + index * 13],
    [0, 1],
    {...clamp, easing: Easing.inOut(Easing.cubic)},
  );
  const width = 1220;
  return (
    <div
      style={{
        position: 'relative',
        height: 106,
        opacity: p,
      }}
    >
      <div
        style={{
          position: 'absolute',
          top: 52,
          left: 190,
          width,
          height: 2,
          background: `linear-gradient(90deg, ${protocol.color}33, ${protocol.color}, ${protocol.color}33)`,
        }}
      />
      <div
        style={{
          position: 'absolute',
          left: 0,
          top: 18,
          display: 'flex',
          alignItems: 'center',
          gap: 16,
          width: 188,
        }}
      >
        <ProtocolMark short={protocol.short} color={protocol.color} size={68} />
        <span
          style={{
            color: colors.ink,
            fontFamily: fonts.body,
            fontSize: 22,
            fontWeight: 750,
            lineHeight: 1.05,
          }}
        >
          {protocol.name}
        </span>
      </div>
      <div
        style={{
          position: 'absolute',
          left: 185 + travel * (width - 105),
          top: 14,
          width: 122,
          height: 78,
          borderRadius: 14,
          border: `1px solid ${protocol.color}`,
          background: shield
            ? `linear-gradient(135deg, ${protocol.color}38, ${colors.panel})`
            : `linear-gradient(135deg, ${protocol.color}1B, ${colors.panel})`,
          boxShadow: `0 0 22px ${protocol.color}35`,
          display: 'grid',
          placeItems: 'center',
          textAlign: 'center',
          color: shield ? protocol.color : colors.ink,
          fontFamily: fonts.mono,
          fontSize: 14,
          lineHeight: 1.3,
          letterSpacing: 1,
          fontWeight: 800,
        }}
      >
        {shield ? (
          <>
            HIDDEN
            <br />
            VALUE
          </>
        ) : (
          <>
            AMOUNT +
            <br />
            HISTORY
          </>
        )}
      </div>
      <div
        style={{
          position: 'absolute',
          right: 0,
          top: 29,
          width: 115,
          height: 52,
          borderRadius: 14,
          border: `1px solid ${colors.line}`,
          color: colors.muted,
          background: colors.panel,
          display: 'grid',
          placeItems: 'center',
          fontFamily: fonts.mono,
          fontSize: 14,
          letterSpacing: 1.5,
        }}
      >
        RECEIVER
      </div>
    </div>
  );
};

const PrivacyScene: React.FC = () => {
  const frame = useCurrentFrame();
  const {fps} = useVideoConfig();
  const records = [
    {
      name: 'SHIELDED CSV',
      color: colors.shielded,
      size: '≈64 B / TX*',
      shape: 'AGGREGATE NULLIFIER',
      detail: 'Schnorr / NISSHAC · amortized after publisher aggregation',
    },
    {
      name: 'ULTRAVIOLET',
      color: colors.uv,
      size: '64 B / SPEND',
      shape: 'nf  ‖  H(private bundle)',
      detail: 'Hash-only record · current carrier transaction is 143–186 vB',
    },
  ];
  return (
    <AbsoluteFill
      style={{
        opacity: sceneOpacity(frame, 300),
        padding: '132px 90px 92px',
      }}
    >
      <Reveal>
        <Kicker>02 / What Bitcoin sees</Kicker>
        <div
          style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'flex-end',
            gap: 60,
          }}
        >
          <div
            style={{
              color: colors.ink,
              fontFamily: fonts.display,
              fontSize: 64,
              lineHeight: 1,
              fontWeight: 900,
              letterSpacing: -3,
            }}
          >
            THE TWO PRIVATE DESIGNS
            <br />LOOK ALMOST THE SAME.
          </div>
          <div
            style={{
              maxWidth: 600,
              color: colors.muted,
              fontFamily: fonts.body,
              fontSize: 25,
              lineHeight: 1.42,
            }}
          >
            Both publish opaque anti-double-spend data. Bitcoin orders it;
            receivers interpret it. The difference is not transfer-chain
            visibility.
          </div>
        </div>
      </Reveal>

      <div
        style={{
          display: 'grid',
          gridTemplateColumns: '1fr 1fr',
          gap: 28,
          marginTop: 42,
        }}
      >
        {records.map((record, index) => {
          const p = enter(frame, fps, 24 + index * 18, 30);
          return (
            <div
              key={record.name}
              style={{
                opacity: p,
                transform: `translateY(${(1 - p) * 36}px)`,
                padding: '31px 34px',
                borderRadius: 26,
                border: `1px solid ${record.color}66`,
                background: `linear-gradient(145deg, ${record.color}13, ${colors.panel})`,
                boxShadow: `0 0 45px ${record.color}16`,
              }}
            >
              <div
                style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  color: record.color,
                  fontFamily: fonts.mono,
                  fontSize: 18,
                  fontWeight: 900,
                  letterSpacing: 2.5,
                }}
              >
                <span>{record.name}</span>
                <span>{record.size}</span>
              </div>
              <div
                style={{
                  marginTop: 30,
                  minHeight: 105,
                  display: 'grid',
                  placeItems: 'center',
                  borderRadius: 18,
                  border: `1px solid ${record.color}36`,
                  background: `${record.color}0B`,
                  color: colors.ink,
                  fontFamily: fonts.display,
                  fontSize: 31,
                  fontWeight: 900,
                  letterSpacing: -1,
                }}
              >
                {record.shape}
              </div>
              <div
                style={{
                  marginTop: 20,
                  color: colors.muted,
                  fontFamily: fonts.body,
                  fontSize: 20,
                  lineHeight: 1.4,
                }}
              >
                {record.detail}
              </div>
            </div>
          );
        })}
      </div>

      <Reveal
        delay={88}
        style={{
          marginTop: 28,
          display: 'grid',
          gridTemplateColumns: '1fr 1fr',
          border: `1px solid ${colors.line}`,
          borderRadius: 22,
          overflow: 'hidden',
          background: 'rgba(17,11,29,.72)',
        }}
      >
        <div style={{padding: '24px 28px'}}>
          <div
            style={{
              color: colors.muted,
              fontFamily: fonts.mono,
              fontSize: 14,
              letterSpacing: 2,
            }}
          >
            PUBLIC SPEND LEAKAGE
          </div>
          <div
            style={{
              marginTop: 9,
              color: colors.ink,
              fontFamily: fonts.body,
              fontSize: 21,
            }}
          >
            Timing, order, and conflicts—not asset, amount, sender, receiver, or
            asset graph.
          </div>
        </div>
        <div
          style={{
            padding: '24px 28px',
            borderLeft: `1px solid ${colors.line}`,
          }}
        >
          <div
            style={{
              color: colors.uvBright,
              fontFamily: fonts.mono,
              fontSize: 14,
              letterSpacing: 2,
            }}
          >
            ULTRAVIOLET ISSUANCE IS DIFFERENT
          </div>
          <div
            style={{
              marginTop: 9,
              color: colors.ink,
              fontFamily: fonts.body,
              fontSize: 21,
            }}
          >
            76 public bytes: tag + amount + asset ID + genesis commitment.
          </div>
        </div>
      </Reveal>
      <div
        style={{
          position: 'absolute',
          right: 90,
          bottom: 45,
          color: colors.muted,
          fontFamily: fonts.mono,
          fontSize: 13,
          letterSpacing: 1.5,
        }}
      >
        * SHIELDED CSV PAPER TARGET · APPLICATION PAYLOAD, NOT FULL BITCOIN TX
      </div>
    </AbsoluteFill>
  );
};

const QuantumScene: React.FC = () => {
  const frame = useCurrentFrame();
  const {fps} = useVideoConfig();
  const scan = interpolate(frame, [35, 190], [0, 1], {
    ...clamp,
    easing: Easing.inOut(Easing.cubic),
  });
  const verdict = enter(frame, fps, 145, 34);
  return (
    <AbsoluteFill
      style={{
        opacity: sceneOpacity(frame, 240),
        padding: '140px 90px 100px',
      }}
    >
      <Reveal>
        <Kicker>03 / The threat model</Kicker>
        <div
          style={{
            color: colors.ink,
            fontFamily: fonts.display,
            fontSize: 70,
            fontWeight: 900,
            letterSpacing: -3,
          }}
        >
          NOW CHANGE THE ADVERSARY.
        </div>
      </Reveal>
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: '1fr 520px',
          gap: 55,
          marginTop: 55,
          alignItems: 'center',
        }}
      >
        <div
          style={{
            border: `1px solid ${colors.line}`,
            borderRadius: 28,
            background: 'rgba(17,11,29,.76)',
            padding: '28px 32px',
            position: 'relative',
            overflow: 'hidden',
          }}
        >
          <div
            style={{
              position: 'absolute',
              top: 0,
              bottom: 0,
              left: `${scan * 100}%`,
              width: 3,
              background: colors.uv,
              boxShadow: `0 0 35px 11px ${colors.uv}66`,
            }}
          />
          {protocols.map((protocol, index) => {
            const seen = scan > 0.12 + index * 0.205;
            return (
              <div
                key={protocol.name}
                style={{
                  height: 116,
                  display: 'grid',
                  gridTemplateColumns: '90px 1fr 340px',
                  alignItems: 'center',
                  borderBottom:
                    index === protocols.length - 1
                      ? 'none'
                      : `1px solid ${colors.line}`,
                  opacity: seen ? 1 : 0.45,
                }}
              >
                <ProtocolMark
                  short={protocol.short}
                  color={protocol.color}
                  size={66}
                  active={protocol.postQuantum && seen}
                />
                <div>
                  <div
                    style={{
                      color: colors.ink,
                      fontFamily: fonts.body,
                      fontWeight: 800,
                      fontSize: 25,
                    }}
                  >
                    {protocol.name}
                  </div>
                  <div
                    style={{
                      color: colors.muted,
                      fontFamily: fonts.mono,
                      fontSize: 15,
                      marginTop: 6,
                      letterSpacing: 1.5,
                    }}
                  >
                    {protocol.owner}
                  </div>
                </div>
                <div
                  style={{
                    justifySelf: 'end',
                    color: protocol.postQuantum
                      ? colors.good
                      : seen
                        ? colors.bad
                        : colors.muted,
                    fontFamily: fonts.mono,
                    fontWeight: 900,
                    fontSize: 18,
                    letterSpacing: 2,
                    border: `1px solid ${
                      protocol.postQuantum ? colors.good : colors.bad
                    }66`,
                    background: `${
                      protocol.postQuantum ? colors.good : colors.bad
                    }10`,
                    borderRadius: 999,
                    padding: '11px 17px',
                  }}
                >
                  {protocol.postQuantum
                    ? 'HASH-BASED / PQ'
                    : 'SCHNORR / CLASSICAL'}
                </div>
              </div>
            );
          })}
        </div>

        <div
          style={{
            opacity: verdict,
            transform: `translateX(${(1 - verdict) * 45}px)`,
          }}
        >
          <div
            style={{
              color: colors.uvBright,
              fontFamily: fonts.mono,
              fontSize: 18,
              letterSpacing: 3,
              fontWeight: 800,
            }}
          >
            ONLY ONE REMOVES THE SPEND SIGNATURE
          </div>
          <div
            style={{
              color: colors.ink,
              fontFamily: fonts.display,
              fontSize: 58,
              fontWeight: 900,
              lineHeight: 1.03,
              letterSpacing: -2,
              marginTop: 18,
            }}
          >
            ANCHOR
            <br />
            PREIMAGE.
            <br />
            HASH-ONLY
            <br />
            MONEY PATH.
          </div>
          <div
            style={{
              marginTop: 28,
              borderLeft: `3px solid ${colors.uv}`,
              paddingLeft: 22,
              color: colors.muted,
              fontFamily: fonts.body,
              fontSize: 23,
              lineHeight: 1.45,
            }}
          >
            Ultraviolet’s theft and forgery assumptions reduce to hash
            security—not elliptic curves.
          </div>
        </div>
      </div>
    </AbsoluteFill>
  );
};

type MatrixValue = {
  text: string;
  tone: 'yes' | 'no' | 'mixed' | 'live' | 'early';
};

const matrixRows: Array<{
  label: string;
  values: MatrixValue[];
}> = [
  {
    label: 'Receive without a UTXO',
    values: [
      {text: 'NO', tone: 'no'},
      {text: 'NO', tone: 'no'},
      {text: 'YES', tone: 'yes'},
      {text: 'YES', tone: 'yes'},
    ],
  },
  {
    label: 'Receive work',
    values: [
      {text: 'O(HISTORY)', tone: 'no'},
      {text: 'O(LINEAGE)', tone: 'no'},
      {text: 'O(1)', tone: 'yes'},
      {text: 'O(HISTORY)', tone: 'mixed'},
    ],
  },
  {
    label: 'Post-quantum ownership',
    values: [
      {text: 'NO', tone: 'no'},
      {text: 'NO', tone: 'no'},
      {text: 'NO', tone: 'no'},
      {text: 'YES', tone: 'yes'},
    ],
  },
  {
    label: 'Production status',
    values: [
      {text: 'MAINNET', tone: 'live'},
      {text: 'MAINNET + LN', tone: 'live'},
      {text: 'PAPER', tone: 'early'},
      {text: 'SIGNET / R&D', tone: 'early'},
    ],
  },
];

const MatrixCell: React.FC<{value: MatrixValue; delay: number}> = ({
  value,
  delay,
}) => {
  const frame = useCurrentFrame();
  const {fps} = useVideoConfig();
  const p = enter(frame, fps, delay, 22);
  const tone =
    value.tone === 'yes'
      ? colors.good
      : value.tone === 'no'
        ? colors.bad
        : value.tone === 'live'
          ? colors.shielded
          : colors.taproot;
  return (
    <div
      style={{
        height: '100%',
        display: 'grid',
        placeItems: 'center',
        color: tone,
        fontFamily: fonts.mono,
        fontSize: value.text.length > 9 ? 16 : 20,
        fontWeight: 900,
        letterSpacing: 1.5,
        opacity: p,
        background: `${tone}08`,
      }}
    >
      {value.text}
    </div>
  );
};

const RealityScene: React.FC = () => {
  const frame = useCurrentFrame();
  return (
    <AbsoluteFill
      style={{
        opacity: sceneOpacity(frame, 255),
        padding: '140px 90px 100px',
      }}
    >
      <Reveal>
        <Kicker>04 / The honest scorecard</Kicker>
        <div
          style={{
            display: 'flex',
            alignItems: 'flex-end',
            justifyContent: 'space-between',
            gap: 45,
          }}
        >
          <div
            style={{
              color: colors.ink,
              fontFamily: fonts.display,
              fontSize: 66,
              fontWeight: 900,
              letterSpacing: -3,
            }}
          >
            ARCHITECTURE ISN’T MATURITY.
          </div>
          <div
            style={{
              color: colors.muted,
              fontFamily: fonts.body,
              fontSize: 24,
              maxWidth: 545,
              lineHeight: 1.4,
            }}
          >
            The incumbents ship. The new designs move the boundary. Those are
            different claims.
          </div>
        </div>
      </Reveal>

      <div
        style={{
          display: 'grid',
          gridTemplateColumns: '390px repeat(4, 1fr)',
          gridTemplateRows: '112px repeat(4, 120px)',
          marginTop: 44,
          border: `1px solid ${colors.line}`,
          borderRadius: 26,
          overflow: 'hidden',
          background: 'rgba(17,11,29,.82)',
        }}
      >
        <div
          style={{
            padding: '28px 32px',
            color: colors.muted,
            fontFamily: fonts.mono,
            fontSize: 16,
            letterSpacing: 2,
            display: 'flex',
            alignItems: 'center',
            borderRight: `1px solid ${colors.line}`,
          }}
        >
          AS OF JULY 2026
        </div>
        {protocols.map((protocol, index) => (
          <div
            key={protocol.name}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 14,
              padding: '18px 20px',
              borderRight:
                index === protocols.length - 1
                  ? 'none'
                  : `1px solid ${colors.line}`,
              background: `${protocol.color}0A`,
            }}
          >
            <ProtocolMark
              short={protocol.short}
              color={protocol.color}
              size={57}
              active={protocol.short === 'UV'}
            />
            <div
              style={{
                color: colors.ink,
                fontFamily: fonts.body,
                fontSize: 20,
                lineHeight: 1.05,
                fontWeight: 800,
              }}
            >
              {protocol.name}
            </div>
          </div>
        ))}
        {matrixRows.flatMap((row, rowIndex) => [
          <div
            key={`${row.label}-label`}
            style={{
              padding: '0 32px',
              display: 'flex',
              alignItems: 'center',
              color: colors.ink,
              fontFamily: fonts.body,
              fontWeight: 750,
              fontSize: 22,
              borderTop: `1px solid ${colors.line}`,
              borderRight: `1px solid ${colors.line}`,
            }}
          >
            {row.label}
          </div>,
          ...row.values.map((value, colIndex) => (
            <div
              key={`${row.label}-${colIndex}`}
              style={{
                borderTop: `1px solid ${colors.line}`,
                borderRight:
                  colIndex === row.values.length - 1
                    ? 'none'
                    : `1px solid ${colors.line}`,
              }}
            >
              <MatrixCell
                value={value}
                delay={30 + rowIndex * 18 + colIndex * 5}
              />
            </div>
          )),
        ])}
      </div>
      <Reveal
        delay={175}
        style={{
          marginTop: 23,
          color: colors.taproot,
          fontFamily: fonts.mono,
          fontSize: 17,
          letterSpacing: 2,
        }}
      >
        ULTRAVIOLET: WORKING CORE + PUBLIC SIGNET DEMO · UNAUDITED · NOT MONEY
      </Reveal>
    </AbsoluteFill>
  );
};

const FinaleScene: React.FC = () => {
  const frame = useCurrentFrame();
  const {fps} = useVideoConfig();
  const p = enter(frame, fps, 10, 36);
  const glow = 0.65 + Math.sin(frame / 18) * 0.22;
  const sweep = interpolate(frame, [10, 150], [-0.2, 1.2], clamp);
  return (
    <AbsoluteFill
      style={{
        opacity: interpolate(frame, [0, 18, 210, 225], [0, 1, 1, 0], clamp),
        display: 'grid',
        placeItems: 'center',
        textAlign: 'center',
        overflow: 'hidden',
      }}
    >
      <div
        style={{
          position: 'absolute',
          width: 1250,
          height: 1250,
          borderRadius: '50%',
          border: `1px solid ${colors.uv}38`,
          boxShadow: `inset 0 0 180px ${colors.uv}18, 0 0 140px ${colors.uv}18`,
          transform: `scale(${0.8 + p * 0.2})`,
        }}
      />
      <div
        style={{
          position: 'absolute',
          left: `${sweep * 100}%`,
          top: -100,
          width: 180,
          height: 1280,
          transform: 'rotate(12deg)',
          background:
            'linear-gradient(90deg, transparent, rgba(168,121,255,.16), transparent)',
        }}
      />
      <div
        style={{
          position: 'relative',
          zIndex: 2,
          opacity: p,
          transform: `scale(${0.9 + p * 0.1})`,
        }}
      >
        <div style={{display: 'grid', placeItems: 'center'}}>
          <ProtocolMark
            short="UV"
            color={colors.uv}
            size={118}
            active
          />
        </div>
        <div
          style={{
            color: colors.uvBright,
            fontFamily: fonts.mono,
            fontSize: 21,
            fontWeight: 800,
            letterSpacing: 5,
            marginTop: 33,
          }}
        >
          COUSINS, NOT STRANGERS
        </div>
        <div
          style={{
            color: colors.ink,
            fontFamily: fonts.display,
            fontSize: 92,
            lineHeight: 0.98,
            fontWeight: 900,
            letterSpacing: -5,
            marginTop: 22,
            textShadow: `0 0 ${40 * glow}px rgba(168,121,255,.32)`,
          }}
        >
          LEARN FROM EACH.
          <br />
          NAME THE TRADEOFF.
          <br />
          <span style={{color: colors.uv}}>BUILD THE NEXT BRANCH.</span>
        </div>
        <div
          style={{
            color: colors.muted,
            fontFamily: fonts.body,
            fontSize: 25,
            marginTop: 32,
          }}
        >
          Bitcoin orders. Holders validate. Ownership, receive work, and
          issuance define the branch.
        </div>
        <div
          style={{
            display: 'inline-flex',
            marginTop: 42,
            border: `1px solid ${colors.uv}77`,
            background: `${colors.uv}13`,
            borderRadius: 999,
            padding: '15px 24px',
            color: colors.uvBright,
            fontFamily: fonts.mono,
            fontSize: 18,
            letterSpacing: 2,
            boxShadow: `0 0 30px ${colors.uv}20`,
          }}
        >
          GITHUB.COM/ULTRAVIENET/ULTRAVIOLET
        </div>
        <div
          style={{
            color: colors.muted,
            fontFamily: fonts.mono,
            fontSize: 14,
            letterSpacing: 1.5,
            marginTop: 26,
          }}
        >
          RESEARCH PROJECT · WORKING CORE · UNAUDITED · DO NOT PUT VALUE ON IT
        </div>
      </div>
    </AbsoluteFill>
  );
};

export const UltravioletComparison: React.FC = () => {
  return (
    <AbsoluteFill
      style={{
        background: colors.bg,
        color: colors.ink,
        fontFamily: fonts.body,
      }}
    >
      <NoiseGrid />
      <Sequence from={0} durationInFrames={210}>
        <IntroScene />
      </Sequence>
      <Sequence from={210} durationInFrames={270}>
        <FieldScene />
      </Sequence>
      <Sequence from={480} durationInFrames={300}>
        <OwnershipScene />
      </Sequence>
      <Sequence from={780} durationInFrames={300}>
        <PrivacyScene />
      </Sequence>
      <Sequence from={1080} durationInFrames={240}>
        <QuantumScene />
      </Sequence>
      <Sequence from={1320} durationInFrames={255}>
        <RealityScene />
      </Sequence>
      <Sequence from={1575} durationInFrames={225}>
        <FinaleScene />
      </Sequence>
      <GlobalChrome />
    </AbsoluteFill>
  );
};
