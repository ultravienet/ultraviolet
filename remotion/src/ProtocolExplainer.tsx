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
  Kicker,
  NoiseGrid,
  ProtocolMark,
  Reveal,
  sceneOpacity,
  SeriesChrome,
} from './components';
import {colors, fonts} from './theme';

type ProtocolId = 'shielded' | 'taproot' | 'rgb';

type ExplainerConfig = {
  id: ProtocolId;
  name: string;
  short: string;
  color: string;
  episode: string;
  status: string;
  title: string;
  subtitle: string;
  modelKicker: string;
  modelTitle: string;
  flowTitle: string;
  flowSteps: Array<{number: string; title: string; body: string}>;
  flowNote: string;
  strengths: Array<{title: string; body: string}>;
  boundaries: Array<{title: string; body: string}>;
  finale: string;
  finaleSub: string;
  source: string;
};

const configs: Record<ProtocolId, ExplainerConfig> = {
  shielded: {
    id: 'shielded',
    name: 'Shielded CSV',
    short: 'CSV',
    color: colors.shielded,
    episode: '02',
    status: 'PAPER · EPRINT 2025/068',
    title: 'PRIVATE COINS.\nPUBLIC DOUBLE-SPEND ORDER.',
    subtitle:
      'A client-side validation design where coin history stays with its holders and Bitcoin receives only the data needed to stop a second spend.',
    modelKicker: 'The architectural move',
    modelTitle: 'THE COIN MOVES PRIVATELY.\nTHE NULLIFIER GOES PUBLIC.',
    flowTitle: 'ONE PAYMENT, THREE SURFACES.',
    flowSteps: [
      {
        number: '01',
        title: 'PROVE',
        body: 'The sender updates private coin state and produces recursive proof-carrying data.',
      },
      {
        number: '02',
        title: 'PUBLISH',
        body: 'A compact 64-byte transaction is ordered by Bitcoin to rule out double spends.',
      },
      {
        number: '03',
        title: 'DELIVER',
        body: 'The receiver gets the new coin and its validity proof directly—not from every node.',
      },
      {
        number: '04',
        title: 'VERIFY',
        body: 'Receive cost stays O(1): past computation is compressed into the current proof.',
      },
    ],
    flowNote:
      'The 64-byte footprint is per transaction, independent of how many coins it spends and creates.',
    strengths: [
      {
        title: 'PRIVATE BY CONSTRUCTION',
        body: 'Amounts and transaction relationships are hidden from the public chain and from later holders.',
      },
      {
        title: 'NO RECEIVE UTXO',
        body: 'Ownership lives in client-side coins, so a receiver does not need a fresh Bitcoin output.',
      },
      {
        title: 'CONSTANT RECEIVE',
        body: 'Recursive PCD compresses the validity history instead of asking every receiver to replay it.',
      },
    ],
    boundaries: [
      {
        title: 'SCHNORR AT THE CORE',
        body: 'Its spend authorization and nullifier checks remain classical—not post-quantum.',
      },
      {
        title: 'RESEARCH, NOT A RAIL',
        body: 'The protocol is a paper and reference design, not a production asset network.',
      },
    ],
    finale: 'THE ARCHITECTURE\nULTRAVIOLET BUILDS ON.',
    finaleSub:
      'Shielded CSV contributed the 64-byte nullifier log, private client-side coins, and proof-carrying validity.',
    source: 'EPRINT.IACR.ORG/2025/068',
  },
  taproot: {
    id: 'taproot',
    name: 'Taproot Assets',
    short: 'TA',
    color: colors.taproot,
    episode: '03',
    status: 'MAINNET · LIGHTNING SHIPPED',
    title: 'ASSETS INSIDE\nTAPROOT OUTPUTS.',
    subtitle:
      'A production protocol that commits asset trees into Bitcoin UTXOs, keeps witness data off-chain, and moves issued assets through Lightning.',
    modelKicker: 'The nested commitment',
    modelTitle: 'ONE BITCOIN OUTPUT.\nA TREE OF ASSET STATE INSIDE.',
    flowTitle: 'HOW AN ON-CHAIN TRANSFER MOVES.',
    flowSteps: [
      {
        number: '01',
        title: 'ADDRESS',
        body: 'The receiver shares an asset ID, script key, internal key, amount, and proof courier.',
      },
      {
        number: '02',
        title: 'UPDATE',
        body: 'The sender rebuilds the Merkle-sum tree so inputs, outputs, and total value still agree.',
      },
      {
        number: '03',
        title: 'ANCHOR',
        body: 'A new Taproot transaction commits the updated asset root into a Bitcoin UTXO.',
      },
      {
        number: '04',
        title: 'PROVE',
        body: 'An off-chain proof file reaches the receiver and is checked back to the genesis output.',
      },
    ],
    flowNote:
      'Universes replicate asset metadata and proofs. They improve availability but cannot forge valid state.',
    strengths: [
      {
        title: 'SHIPPED TODAY',
        body: 'Mainnet software, static addresses, multi-asset channels, and issued assets moving over Lightning.',
      },
      {
        title: 'EXCELLENT UNIFORMITY',
        body: 'The public anchor looks like an ordinary Taproot output; detailed asset witness data stays off-chain.',
      },
      {
        title: 'LIGHTNING REACH',
        body: 'Edge nodes swap the asset into BTC liquidity so wallets can reach the broader Lightning Network.',
      },
    ],
    boundaries: [
      {
        title: 'LINEAGE GROWS',
        body: 'Each proof is audited back to genesis and grows linearly with on-chain asset history.',
      },
      {
        title: 'UTXO + SCHNORR',
        body: 'A holder needs a Taproot UTXO, and ownership inherits Bitcoin’s classical key assumptions.',
      },
    ],
    finale: 'THE STRONGEST SHIPPED\nASSET RAIL ON BITCOIN.',
    finaleSub:
      'Taproot Assets is excellent engineering inside the classical, UTXO-bound model.',
    source: 'DOCS.LIGHTNING.ENGINEERING / TAPROOT ASSETS',
  },
  rgb: {
    id: 'rgb',
    name: 'RGB',
    short: 'RGB',
    color: colors.rgb,
    episode: '04',
    status: 'MAINNET · CLIENT-SIDE CONTRACTS',
    title: 'CONTRACT STATE\nTHAT BITCOIN NEVER SEES.',
    subtitle:
      'RGB keeps smart-contract history with its participants and uses Bitcoin UTXOs as single-use seals that can close exactly once.',
    modelKicker: 'The foundational idea',
    modelTitle: 'BITCOIN CLOSES THE SEAL.\nTHE RECEIVER CHECKS THE CONTRACT.',
    flowTitle: 'A CONSIGNMENT CHANGES HANDS.',
    flowSteps: [
      {
        number: '01',
        title: 'SEAL',
        body: 'A Bitcoin outpoint defines the current single-use seal for the asset state.',
      },
      {
        number: '02',
        title: 'TRANSITION',
        body: 'The sender creates the next contract state and commits it into the seal-closing transaction.',
      },
      {
        number: '03',
        title: 'CONSIGN',
        body: 'The relevant state history travels privately from sender to receiver as a consignment.',
      },
      {
        number: '04',
        title: 'REPLAY',
        body: 'The receiver validates the contract and every seal transition back through its history.',
      },
    ],
    flowNote:
      'Bitcoin enforces uniqueness: one UTXO can be spent only once, so the seal cannot be closed twice.',
    strengths: [
      {
        title: 'GENERAL CONTRACTS',
        body: 'RGB is broader than a payment format: schema and validation logic define client-side smart contracts.',
      },
      {
        title: 'NO GLOBAL ASSET STATE',
        body: 'Bitcoin nodes do not execute or store the contract; only involved holders keep the relevant history.',
      },
      {
        title: 'LIGHT SEND PATH',
        body: 'There is no validity prover. A sender constructs the transition and hands over the consignment.',
      },
    ],
    boundaries: [
      {
        title: 'RECEIVER REPLAYS HISTORY',
        body: 'Validation and settlement work grow with the asset’s chain of custody.',
      },
      {
        title: 'UTXO + SCHNORR',
        body: 'Receiving needs a new seal, and the anchor remains exposed to classical key assumptions.',
      },
    ],
    finale: 'SEND LIGHT.\nVERIFY THE WHOLE STORY.',
    finaleSub:
      'RGB made client-side validation practical. Its cost appears when every new holder replays the past.',
    source: 'DOCS.RGB.INFO / CLIENT-SIDE VALIDATION',
  },
};

const EpisodeChrome: React.FC<{config: ExplainerConfig}> = ({config}) => (
  <SeriesChrome
    label={`ULTRAVIOLET / FIELD NOTES ${config.episode}`}
    accent={config.color}
  />
);

const SceneTitle: React.FC<{
  kicker: string;
  title: string;
  color: string;
}> = ({kicker, title, color}) => (
  <Reveal>
    <Kicker color={color}>{kicker}</Kicker>
    <div
      style={{
        color: colors.ink,
        fontFamily: fonts.display,
        fontWeight: 900,
        fontSize: 68,
        lineHeight: 1,
        letterSpacing: -3,
        whiteSpace: 'pre-line',
      }}
    >
      {title}
    </div>
  </Reveal>
);

const IntroScene: React.FC<{config: ExplainerConfig}> = ({config}) => {
  const frame = useCurrentFrame();
  const {fps} = useVideoConfig();
  const p = enter(frame, fps, 16, 38);
  const orbit = interpolate(frame, [20, 145], [0.82, 1], {
    ...clamp,
    easing: Easing.out(Easing.cubic),
  });
  return (
    <AbsoluteFill
      style={{
        opacity: sceneOpacity(frame, 180),
        padding: '145px 110px 100px',
        justifyContent: 'center',
      }}
    >
      <div
        style={{
          position: 'absolute',
          right: 95,
          top: 125,
          width: 760,
          height: 760,
          border: `1px solid ${config.color}3D`,
          borderRadius: '50%',
          transform: `scale(${orbit})`,
          boxShadow: `inset 0 0 120px ${config.color}12`,
        }}
      />
      <div
        style={{
          position: 'absolute',
          right: 350,
          top: 370,
          transform: `scale(${p}) rotate(${(1 - p) * -12}deg)`,
        }}
      >
        <ProtocolMark
          short={config.short}
          color={config.color}
          size={230}
          active
        />
      </div>
      <div
        style={{
          width: 1040,
          opacity: p,
          transform: `translateX(${(1 - p) * -55}px)`,
        }}
      >
        <Kicker color={config.color}>{config.status}</Kicker>
        <div
          style={{
            color: colors.ink,
            fontFamily: fonts.display,
            fontSize: 100,
            fontWeight: 900,
            lineHeight: 0.96,
            letterSpacing: -5,
            whiteSpace: 'pre-line',
          }}
        >
          {config.title}
        </div>
        <div
          style={{
            color: colors.muted,
            fontFamily: fonts.body,
            fontSize: 28,
            lineHeight: 1.45,
            marginTop: 30,
            maxWidth: 880,
          }}
        >
          {config.subtitle}
        </div>
      </div>
    </AbsoluteFill>
  );
};

const ShieldedModel: React.FC<{color: string}> = ({color}) => {
  const frame = useCurrentFrame();
  const {fps} = useVideoConfig();
  const nodes = [
    {x: 0, label: 'SENDER', sub: 'private coin + witness'},
    {x: 1, label: 'BITCOIN', sub: '64-byte transaction'},
    {x: 2, label: 'RECEIVER', sub: 'new coin + PCD'},
  ];
  const line = interpolate(frame, [40, 130], [0, 1], clamp);
  return (
    <div
      style={{
        display: 'grid',
        gridTemplateColumns: '1fr 1fr 1fr',
        gap: 30,
        alignItems: 'center',
        position: 'relative',
        marginTop: 58,
      }}
    >
      <div
        style={{
          position: 'absolute',
          left: '14%',
          right: '14%',
          top: 98,
          height: 2,
          background: `linear-gradient(90deg, ${color}, ${colors.bitcoin}, ${color})`,
          transform: `scaleX(${line})`,
        }}
      />
      {nodes.map((node, index) => {
        const p = enter(frame, fps, 24 + index * 18, 28);
        return (
          <div
            key={node.label}
            style={{
              zIndex: 1,
              opacity: p,
              transform: `translateY(${(1 - p) * 34}px)`,
              height: 290,
              padding: 28,
              border: `1px solid ${
                index === 1 ? colors.bitcoin : color
              }66`,
              borderRadius: 26,
              background:
                index === 1
                  ? `linear-gradient(145deg, ${colors.bitcoin}16, ${colors.panel})`
                  : `linear-gradient(145deg, ${color}16, ${colors.panel})`,
              textAlign: 'center',
              display: 'grid',
              placeItems: 'center',
            }}
          >
            <div>
              <div
                style={{
                  width: index === 1 ? 126 : 154,
                  height: index === 1 ? 80 : 106,
                  borderRadius: 20,
                  border: `2px solid ${
                    index === 1 ? colors.bitcoin : color
                  }`,
                  display: 'grid',
                  placeItems: 'center',
                  margin: '0 auto 25px',
                  color: index === 1 ? colors.bitcoin : color,
                  fontFamily: fonts.mono,
                  fontWeight: 900,
                  fontSize: index === 1 ? 19 : 22,
                  boxShadow: `0 0 28px ${
                    index === 1 ? colors.bitcoin : color
                  }30`,
                }}
              >
                {index === 1 ? '64 BYTES' : index === 0 ? 'COIN' : 'PCD ✓'}
              </div>
              <div
                style={{
                  color: colors.ink,
                  fontFamily: fonts.display,
                  fontSize: 28,
                  fontWeight: 900,
                }}
              >
                {node.label}
              </div>
              <div
                style={{
                  color: colors.muted,
                  fontFamily: fonts.mono,
                  fontSize: 15,
                  letterSpacing: 1.2,
                  marginTop: 10,
                }}
              >
                {node.sub}
              </div>
            </div>
          </div>
        );
      })}
    </div>
  );
};

const TaprootModel: React.FC<{color: string}> = ({color}) => {
  const frame = useCurrentFrame();
  const {fps} = useVideoConfig();
  const layers = [
    {label: 'BITCOIN UTXO', color: colors.bitcoin, inset: 0},
    {label: 'TAPROOT COMMITMENT', color, inset: 50},
    {label: 'ASSET MERKLE-SUM TREE', color, inset: 100},
  ];
  return (
    <div
      style={{
        display: 'grid',
        gridTemplateColumns: '1.25fr .75fr',
        gap: 40,
        marginTop: 48,
        alignItems: 'stretch',
      }}
    >
      <div style={{height: 370, position: 'relative'}}>
        {layers.map((layer, index) => {
          const p = enter(frame, fps, 20 + index * 18, 30);
          return (
            <div
              key={layer.label}
              style={{
                position: 'absolute',
                inset: layer.inset,
                border: `2px solid ${layer.color}`,
                borderRadius: 30 - index * 4,
                background: `${layer.color}${index === 0 ? '09' : '10'}`,
                boxShadow:
                  index === 2 ? `inset 0 0 45px ${color}18` : 'none',
                opacity: p,
                transform: `scale(${0.94 + p * 0.06})`,
              }}
            >
              <div
                style={{
                  position: 'absolute',
                  left: 22,
                  top: 18,
                  color: layer.color,
                  fontFamily: fonts.mono,
                  fontSize: 16,
                  fontWeight: 900,
                  letterSpacing: 2,
                }}
              >
                {layer.label}
              </div>
            </div>
          );
        })}
        <div
          style={{
            position: 'absolute',
            inset: 142,
            display: 'flex',
            justifyContent: 'center',
            gap: 15,
          }}
        >
          {[12, 8, 4, 10, 6].map((height, index) => (
            <div
              key={index}
              style={{
                width: 58,
                height: 44 + height * 2,
                alignSelf: 'flex-end',
                border: `1px solid ${color}`,
                background: `${color}${15 + index * 4}`,
                borderRadius: 9,
              }}
            />
          ))}
        </div>
      </div>
      <Reveal delay={65}>
        <div
          style={{
            height: 370,
            padding: 34,
            border: `1px solid ${color}66`,
            borderRadius: 26,
            background: `linear-gradient(145deg, ${color}14, ${colors.panel})`,
          }}
        >
          <div
            style={{
              color,
              fontFamily: fonts.mono,
              fontSize: 18,
              fontWeight: 900,
              letterSpacing: 2,
            }}
          >
            OFF-CHAIN
          </div>
          <div
            style={{
              color: colors.ink,
              fontFamily: fonts.display,
              fontSize: 36,
              fontWeight: 900,
              marginTop: 18,
            }}
          >
            PROOF FILE
          </div>
          <div
            style={{
              color: colors.muted,
              fontFamily: fonts.body,
              fontSize: 22,
              lineHeight: 1.45,
              marginTop: 22,
            }}
          >
            Witness data, Merkle paths, signatures, and lineage travel between
            asset clients—not through every Bitcoin node.
          </div>
          <div
            style={{
              marginTop: 28,
              color,
              fontFamily: fonts.mono,
              fontSize: 15,
              letterSpacing: 1.4,
            }}
          >
            VERIFIED BACK TO GENESIS
          </div>
        </div>
      </Reveal>
    </div>
  );
};

const RgbModel: React.FC<{color: string}> = ({color}) => {
  const frame = useCurrentFrame();
  const line = interpolate(frame, [30, 135], [0, 1], clamp);
  return (
    <div style={{marginTop: 58}}>
      <div
        style={{
          position: 'relative',
          display: 'grid',
          gridTemplateColumns: 'repeat(4, 1fr)',
          gap: 32,
        }}
      >
        <div
          style={{
            position: 'absolute',
            left: '10%',
            right: '10%',
            top: 55,
            height: 3,
            background: `linear-gradient(90deg, ${colors.bitcoin}, ${color})`,
            transform: `scaleX(${line})`,
            transformOrigin: 'left',
          }}
        />
        {['UTXO A', 'UTXO B', 'UTXO C', 'UTXO D'].map((label, index) => (
          <Reveal key={label} delay={20 + index * 16}>
            <div style={{textAlign: 'center', position: 'relative'}}>
              <div
                style={{
                  width: 150,
                  height: 110,
                  margin: '0 auto',
                  border: `2px solid ${
                    index === 3 ? color : colors.bitcoin
                  }`,
                  borderRadius: 22,
                  background:
                    index === 3
                      ? `linear-gradient(${color}18, ${color}18), ${colors.bgRaised}`
                      : `linear-gradient(${colors.bitcoin}10, ${colors.bitcoin}10), ${colors.bgRaised}`,
                  display: 'grid',
                  placeItems: 'center',
                  color: index === 3 ? color : colors.bitcoin,
                  fontFamily: fonts.mono,
                  fontSize: 20,
                  fontWeight: 900,
                  boxShadow:
                    index === 3 ? `0 0 30px ${color}32` : 'none',
                }}
              >
                {label}
              </div>
              <div
                style={{
                  color: colors.ink,
                  fontFamily: fonts.display,
                  fontSize: 24,
                  fontWeight: 900,
                  marginTop: 22,
                }}
              >
                {index === 0 ? 'ISSUE' : `TRANSFER ${index}`}
              </div>
            </div>
          </Reveal>
        ))}
      </div>
      <Reveal delay={90}>
        <div
          style={{
            marginTop: 38,
            padding: '24px 30px',
            borderRadius: 22,
            border: `1px solid ${color}55`,
            background: `${color}0D`,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
          }}
        >
          <div>
            <div
              style={{
                color,
                fontFamily: fonts.mono,
                fontSize: 16,
                fontWeight: 900,
                letterSpacing: 2,
              }}
            >
              PRIVATE CONSIGNMENT
            </div>
            <div
              style={{
                color: colors.ink,
                fontFamily: fonts.body,
                fontSize: 24,
                fontWeight: 700,
                marginTop: 8,
              }}
            >
              Contract state + every relevant transition
            </div>
          </div>
          <div
            style={{
              color: colors.muted,
              fontFamily: fonts.mono,
              fontSize: 17,
              letterSpacing: 1.5,
            }}
          >
            SENDER → RECEIVER
          </div>
        </div>
      </Reveal>
    </div>
  );
};

const ModelScene: React.FC<{config: ExplainerConfig}> = ({config}) => {
  const frame = useCurrentFrame();
  return (
    <AbsoluteFill
      style={{
        opacity: sceneOpacity(frame, 300),
        padding: '135px 90px 90px',
      }}
    >
      <SceneTitle
        kicker={config.modelKicker}
        title={config.modelTitle}
        color={config.color}
      />
      {config.id === 'shielded' ? (
        <ShieldedModel color={config.color} />
      ) : config.id === 'taproot' ? (
        <TaprootModel color={config.color} />
      ) : (
        <RgbModel color={config.color} />
      )}
    </AbsoluteFill>
  );
};

const FlowScene: React.FC<{config: ExplainerConfig}> = ({config}) => {
  const frame = useCurrentFrame();
  const {fps} = useVideoConfig();
  const track = interpolate(frame, [30, 145], [0, 1], {
    ...clamp,
    easing: Easing.out(Easing.cubic),
  });
  return (
    <AbsoluteFill
      style={{
        opacity: sceneOpacity(frame, 300),
        padding: '135px 90px 90px',
      }}
    >
      <SceneTitle
        kicker="The transfer"
        title={config.flowTitle}
        color={config.color}
      />
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(4, 1fr)',
          gap: 24,
          marginTop: 55,
          position: 'relative',
        }}
      >
        <div
          style={{
            position: 'absolute',
            left: '8%',
            right: '8%',
            top: 52,
            height: 2,
            background: `linear-gradient(90deg, ${config.color}44, ${config.color})`,
            transform: `scaleX(${track})`,
            transformOrigin: 'left',
          }}
        />
        {config.flowSteps.map((step, index) => {
          const p = enter(frame, fps, 20 + index * 17, 28);
          return (
            <div
              key={step.number}
              style={{
                opacity: p,
                transform: `translateY(${(1 - p) * 50}px)`,
                position: 'relative',
                zIndex: 1,
              }}
            >
              <div
                style={{
                  width: 104,
                  height: 104,
                  borderRadius: '50%',
                  border: `2px solid ${config.color}`,
                  background: colors.bgRaised,
                  display: 'grid',
                  placeItems: 'center',
                  color: config.color,
                  fontFamily: fonts.mono,
                  fontSize: 22,
                  fontWeight: 900,
                  boxShadow: `0 0 28px ${config.color}32`,
                }}
              >
                {step.number}
              </div>
              <div
                style={{
                  marginTop: 25,
                  color: colors.ink,
                  fontFamily: fonts.display,
                  fontSize: 31,
                  fontWeight: 900,
                }}
              >
                {step.title}
              </div>
              <div
                style={{
                  marginTop: 15,
                  color: colors.muted,
                  fontFamily: fonts.body,
                  fontSize: 22,
                  lineHeight: 1.42,
                  maxWidth: 365,
                }}
              >
                {step.body}
              </div>
            </div>
          );
        })}
      </div>
      <Reveal
        delay={155}
        style={{
          marginTop: 46,
          padding: '20px 26px',
          borderLeft: `3px solid ${config.color}`,
          background: `${config.color}0C`,
          color: colors.ink,
          fontFamily: fonts.body,
          fontSize: 23,
        }}
      >
        {config.flowNote}
      </Reveal>
    </AbsoluteFill>
  );
};

const PointCard: React.FC<{
  point: {title: string; body: string};
  color: string;
  delay: number;
  index: number;
}> = ({point, color, delay, index}) => (
  <Reveal delay={delay} y={35}>
    <div
      style={{
        padding: '25px 28px',
        border: `1px solid ${color}40`,
        borderRadius: 20,
        background: `${color}08`,
        display: 'grid',
        gridTemplateColumns: '52px 1fr',
        gap: 18,
      }}
    >
      <div
        style={{
          color,
          fontFamily: fonts.mono,
          fontWeight: 900,
          fontSize: 17,
          letterSpacing: 1.5,
        }}
      >
        0{index + 1}
      </div>
      <div>
        <div
          style={{
            color: colors.ink,
            fontFamily: fonts.display,
            fontSize: 24,
            fontWeight: 900,
          }}
        >
          {point.title}
        </div>
        <div
          style={{
            color: colors.muted,
            fontFamily: fonts.body,
            fontSize: 20,
            lineHeight: 1.4,
            marginTop: 9,
          }}
        >
          {point.body}
        </div>
      </div>
    </div>
  </Reveal>
);

const TradeoffsScene: React.FC<{config: ExplainerConfig}> = ({config}) => {
  const frame = useCurrentFrame();
  return (
    <AbsoluteFill
      style={{
        opacity: sceneOpacity(frame, 300),
        padding: '135px 90px 90px',
      }}
    >
      <SceneTitle
        kicker="What it buys · what it keeps"
        title="THE HONEST BOUNDARY."
        color={config.color}
      />
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: '1.15fr .85fr',
          gap: 28,
          marginTop: 50,
        }}
      >
        <div
          style={{
            border: `1px solid ${config.color}55`,
            borderRadius: 26,
            padding: 28,
            background: `linear-gradient(145deg, ${config.color}11, ${colors.panel})`,
          }}
        >
          <div
            style={{
              color: config.color,
              fontFamily: fonts.mono,
              fontSize: 17,
              fontWeight: 900,
              letterSpacing: 2.5,
              marginBottom: 18,
            }}
          >
            STRENGTHS
          </div>
          <div style={{display: 'grid', gap: 14}}>
            {config.strengths.map((point, index) => (
              <PointCard
                key={point.title}
                point={point}
                color={config.color}
                delay={20 + index * 16}
                index={index}
              />
            ))}
          </div>
        </div>
        <div
          style={{
            border: `1px solid ${colors.bad}45`,
            borderRadius: 26,
            padding: 28,
            background: `linear-gradient(145deg, ${colors.bad}0C, ${colors.panel})`,
          }}
        >
          <div
            style={{
              color: colors.bad,
              fontFamily: fonts.mono,
              fontSize: 17,
              fontWeight: 900,
              letterSpacing: 2.5,
              marginBottom: 18,
            }}
          >
            BOUNDARIES
          </div>
          <div style={{display: 'grid', gap: 14}}>
            {config.boundaries.map((point, index) => (
              <PointCard
                key={point.title}
                point={point}
                color={colors.bad}
                delay={36 + index * 20}
                index={index}
              />
            ))}
          </div>
          <Reveal delay={110}>
            <div
              style={{
                marginTop: 20,
                borderRadius: 999,
                border: `1px solid ${config.color}55`,
                color: config.color,
                padding: '12px 16px',
                textAlign: 'center',
                fontFamily: fonts.mono,
                fontSize: 15,
                fontWeight: 900,
                letterSpacing: 1.7,
              }}
            >
              {config.status}
            </div>
          </Reveal>
        </div>
      </div>
    </AbsoluteFill>
  );
};

const FinaleScene: React.FC<{config: ExplainerConfig}> = ({config}) => {
  const frame = useCurrentFrame();
  const {fps} = useVideoConfig();
  const p = enter(frame, fps, 10, 38);
  const sweep = interpolate(frame, [10, 190], [-0.2, 1.2], clamp);
  return (
    <AbsoluteFill
      style={{
        opacity: sceneOpacity(frame, 270),
        display: 'grid',
        placeItems: 'center',
        textAlign: 'center',
        overflow: 'hidden',
      }}
    >
      <div
        style={{
          position: 'absolute',
          left: `${sweep * 100}%`,
          top: -120,
          width: 220,
          height: 1320,
          transform: 'rotate(12deg)',
          background: `linear-gradient(90deg, transparent, ${config.color}22, transparent)`,
        }}
      />
      <div
        style={{
          position: 'absolute',
          width: 1120,
          height: 1120,
          border: `1px solid ${config.color}38`,
          borderRadius: '50%',
          boxShadow: `inset 0 0 150px ${config.color}14`,
          transform: `scale(${0.88 + p * 0.12})`,
        }}
      />
      <div
        style={{
          position: 'relative',
          opacity: p,
          transform: `scale(${0.92 + p * 0.08})`,
        }}
      >
        <div style={{display: 'grid', placeItems: 'center'}}>
          <ProtocolMark
            short={config.short}
            color={config.color}
            size={116}
            active
          />
        </div>
        <Kicker color={config.color}>{config.name}</Kicker>
        <div
          style={{
            color: colors.ink,
            fontFamily: fonts.display,
            fontWeight: 900,
            fontSize: 86,
            lineHeight: 0.98,
            letterSpacing: -4,
            whiteSpace: 'pre-line',
            textShadow: `0 0 35px ${config.color}30`,
          }}
        >
          {config.finale}
        </div>
        <div
          style={{
            maxWidth: 940,
            margin: '28px auto 0',
            color: colors.muted,
            fontFamily: fonts.body,
            fontSize: 26,
            lineHeight: 1.4,
          }}
        >
          {config.finaleSub}
        </div>
        <div
          style={{
            display: 'inline-flex',
            marginTop: 36,
            padding: '14px 22px',
            border: `1px solid ${config.color}66`,
            borderRadius: 999,
            color: config.color,
            fontFamily: fonts.mono,
            fontSize: 16,
            letterSpacing: 2,
          }}
        >
          {config.source}
        </div>
      </div>
    </AbsoluteFill>
  );
};

const ProtocolExplainer: React.FC<{id: ProtocolId}> = ({id}) => {
  const config = configs[id];
  return (
    <AbsoluteFill
      style={{
        background: colors.bg,
        color: colors.ink,
        fontFamily: fonts.body,
      }}
    >
      <NoiseGrid accent={config.color} />
      <Sequence from={0} durationInFrames={180}>
        <IntroScene config={config} />
      </Sequence>
      <Sequence from={180} durationInFrames={300}>
        <ModelScene config={config} />
      </Sequence>
      <Sequence from={480} durationInFrames={300}>
        <FlowScene config={config} />
      </Sequence>
      <Sequence from={780} durationInFrames={300}>
        <TradeoffsScene config={config} />
      </Sequence>
      <Sequence from={1080} durationInFrames={270}>
        <FinaleScene config={config} />
      </Sequence>
      <EpisodeChrome config={config} />
    </AbsoluteFill>
  );
};

export const ShieldedCsvExplainer: React.FC = () => (
  <ProtocolExplainer id="shielded" />
);

export const TaprootAssetsExplainer: React.FC = () => (
  <ProtocolExplainer id="taproot" />
);

export const RgbExplainer: React.FC = () => <ProtocolExplainer id="rgb" />;
