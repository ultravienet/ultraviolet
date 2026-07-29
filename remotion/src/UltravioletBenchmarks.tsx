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

const ACCENT = colors.uv;

const BenchTitle: React.FC<{
  kicker: string;
  title: string;
  aside?: string;
}> = ({kicker, title, aside}) => (
  <Reveal>
    <Kicker color={ACCENT}>{kicker}</Kicker>
    <div
      style={{
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'flex-end',
        gap: 50,
      }}
    >
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
      {aside ? (
        <div
          style={{
            maxWidth: 530,
            color: colors.muted,
            fontFamily: fonts.body,
            fontSize: 24,
            lineHeight: 1.42,
          }}
        >
          {aside}
        </div>
      ) : null}
    </div>
  </Reveal>
);

const BenchIntro: React.FC = () => {
  const frame = useCurrentFrame();
  const {fps} = useVideoConfig();
  const p = enter(frame, fps, 15, 38);
  const number = interpolate(frame, [28, 120], [1.5, 0.3], {
    ...clamp,
    easing: Easing.out(Easing.cubic),
  });
  return (
    <AbsoluteFill
      style={{
        opacity: sceneOpacity(frame, 180),
        padding: '145px 110px 95px',
        justifyContent: 'center',
      }}
    >
      <div
        style={{
          position: 'absolute',
          right: 90,
          top: 130,
          width: 735,
          height: 735,
          border: `1px solid ${ACCENT}38`,
          borderRadius: '50%',
          boxShadow: `inset 0 0 130px ${ACCENT}14`,
        }}
      />
      <div
        style={{
          position: 'absolute',
          right: 205,
          top: 340,
          width: 510,
          textAlign: 'center',
          opacity: p,
        }}
      >
        <div
          style={{
            color: ACCENT,
            fontFamily: fonts.display,
            fontSize: 150,
            fontWeight: 900,
            letterSpacing: -10,
            textShadow: `0 0 46px ${ACCENT}48`,
          }}
        >
          {number.toFixed(1)}s
        </div>
        <div
          style={{
            color: colors.muted,
            fontFamily: fonts.mono,
            fontSize: 18,
            letterSpacing: 3,
          }}
        >
          PRIVATE PROOF · ON A PHONE
        </div>
      </div>
      <div
        style={{
          width: 1050,
          opacity: p,
          transform: `translateX(${(1 - p) * -55}px)`,
        }}
      >
        <Kicker color={ACCENT}>Measured · CPU only · July 2026</Kicker>
        <div
          style={{
            color: colors.ink,
            fontFamily: fonts.display,
            fontSize: 101,
            lineHeight: 0.96,
            letterSpacing: -5,
            fontWeight: 900,
          }}
        >
          WHAT DOES ONE
          <br />
          PRIVATE PAYMENT
          <br />
          <span style={{color: ACCENT}}>ACTUALLY COST?</span>
        </div>
        <div
          style={{
            color: colors.muted,
            fontFamily: fonts.body,
            fontSize: 28,
            lineHeight: 1.45,
            marginTop: 28,
            maxWidth: 820,
          }}
        >
          No projection. No proving service. The finished Ultraviolet circuit
          on a laptop and two physical iPhones.
        </div>
      </div>
    </AbsoluteFill>
  );
};

const CircuitScene: React.FC = () => {
  const frame = useCurrentFrame();
  const {fps} = useVideoConfig();
  const checks = [
    'OPEN INPUT',
    'DERIVE NULLIFIER',
    'OPEN OUTPUTS',
    'CONSERVE VALUE',
    'PROVE OWNERSHIP',
    'VERIFY WOTS+',
  ];
  return (
    <AbsoluteFill
      style={{
        opacity: sceneOpacity(frame, 300),
        padding: '135px 90px 90px',
      }}
    >
      <BenchTitle
        kicker="01 / The circuit"
        title={'ONE HOP.\nONE TABLE.'}
        aside="The full money path is expressed as one hand-written AIR: authorization, conservation, commitments, and the spend marker together."
      />
      <div
        style={{
          marginTop: 48,
          display: 'grid',
          gridTemplateColumns: '580px 1fr',
          gap: 36,
          alignItems: 'stretch',
        }}
      >
        <Reveal delay={18}>
          <div
            style={{
              height: 500,
              border: `1px solid ${ACCENT}70`,
              borderRadius: 28,
              background: `linear-gradient(145deg, ${ACCENT}18, ${colors.panel})`,
              boxShadow: `0 0 45px ${ACCENT}20`,
              display: 'grid',
              placeItems: 'center',
              textAlign: 'center',
            }}
          >
            <div>
              <div
                style={{
                  color: colors.ink,
                  fontFamily: fonts.display,
                  fontSize: 100,
                  fontWeight: 900,
                  letterSpacing: -6,
                }}
              >
                1,024
              </div>
              <div
                style={{
                  color: ACCENT,
                  fontFamily: fonts.mono,
                  fontSize: 22,
                  fontWeight: 900,
                  letterSpacing: 3,
                }}
              >
                ROWS
              </div>
              <div
                style={{
                  color: colors.muted,
                  fontFamily: fonts.display,
                  fontSize: 46,
                  margin: '20px 0',
                }}
              >
                ×
              </div>
              <div
                style={{
                  color: colors.ink,
                  fontFamily: fonts.display,
                  fontSize: 100,
                  fontWeight: 900,
                  letterSpacing: -6,
                }}
              >
                457
              </div>
              <div
                style={{
                  color: ACCENT,
                  fontFamily: fonts.mono,
                  fontSize: 22,
                  fontWeight: 900,
                  letterSpacing: 3,
                }}
              >
                COLUMNS
              </div>
            </div>
          </div>
        </Reveal>
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: '1fr 1fr',
            gap: 18,
          }}
        >
          {checks.map((check, index) => {
            const p = enter(frame, fps, 25 + index * 13, 25);
            return (
              <div
                key={check}
                style={{
                  opacity: p,
                  transform: `translateY(${(1 - p) * 28}px)`,
                  border: `1px solid ${ACCENT}38`,
                  borderRadius: 20,
                  background: `${ACCENT}09`,
                  padding: 24,
                  display: 'flex',
                  alignItems: 'center',
                  gap: 18,
                }}
              >
                <div
                  style={{
                    width: 45,
                    height: 45,
                    borderRadius: '50%',
                    border: `1px solid ${colors.good}`,
                    color: colors.good,
                    display: 'grid',
                    placeItems: 'center',
                    fontFamily: fonts.mono,
                    fontSize: 18,
                    fontWeight: 900,
                  }}
                >
                  ✓
                </div>
                <div
                  style={{
                    color: colors.ink,
                    fontFamily: fonts.mono,
                    fontSize: 18,
                    fontWeight: 900,
                    letterSpacing: 1.4,
                  }}
                >
                  {check}
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </AbsoluteFill>
  );
};

type Metric = {
  label: string;
  standard: string;
  hiding: string;
  standardValue: number;
  hidingValue: number;
  unit: string;
};

const laptopMetrics: Metric[] = [
  {
    label: 'PROVE',
    standard: '0.070–0.084 s',
    hiding: '0.202–0.241 s',
    standardValue: 0.077,
    hidingValue: 0.222,
    unit: 'seconds',
  },
  {
    label: 'PROOF',
    standard: '158.3 KB',
    hiding: '208.0 KB',
    standardValue: 158.3,
    hidingValue: 208,
    unit: 'kilobytes',
  },
  {
    label: 'VERIFY',
    standard: '1.4 ms',
    hiding: '1.6 ms',
    standardValue: 1.4,
    hidingValue: 1.6,
    unit: 'milliseconds',
  },
  {
    label: 'PEAK',
    standard: '67 MB',
    hiding: '117 MB',
    standardValue: 67,
    hidingValue: 117,
    unit: 'megabytes',
  },
];

const MetricBars: React.FC<{metric: Metric; index: number}> = ({
  metric,
  index,
}) => {
  const frame = useCurrentFrame();
  const max = Math.max(metric.standardValue, metric.hidingValue);
  const progress = interpolate(
    frame,
    [30 + index * 12, 95 + index * 12],
    [0, 1],
    {...clamp, easing: Easing.out(Easing.cubic)},
  );
  return (
    <div
      style={{
        display: 'grid',
        gridTemplateColumns: '160px 1fr 1fr',
        gap: 22,
        alignItems: 'center',
        padding: '22px 0',
        borderBottom:
          index === laptopMetrics.length - 1
            ? 'none'
            : `1px solid ${colors.line}`,
      }}
    >
      <div
        style={{
          color: colors.ink,
          fontFamily: fonts.mono,
          fontSize: 18,
          fontWeight: 900,
          letterSpacing: 2,
        }}
      >
        {metric.label}
      </div>
      {[
        {
          text: metric.standard,
          value: metric.standardValue,
          color: colors.shielded,
        },
        {text: metric.hiding, value: metric.hidingValue, color: ACCENT},
      ].map((bar) => (
        <div key={bar.text}>
          <div
            style={{
              color: bar.color,
              fontFamily: fonts.display,
              fontSize: 28,
              fontWeight: 900,
              marginBottom: 10,
            }}
          >
            {bar.text}
          </div>
          <div
            style={{
              height: 11,
              borderRadius: 20,
              background: colors.line,
              overflow: 'hidden',
            }}
          >
            <div
              style={{
                height: '100%',
                width: `${(bar.value / max) * progress * 100}%`,
                borderRadius: 20,
                background: bar.color,
                boxShadow: `0 0 16px ${bar.color}`,
              }}
            />
          </div>
        </div>
      ))}
    </div>
  );
};

const LaptopScene: React.FC = () => {
  const frame = useCurrentFrame();
  return (
    <AbsoluteFill
      style={{
        opacity: sceneOpacity(frame, 300),
        padding: '135px 90px 90px',
      }}
    >
      <BenchTitle
        kicker="02 / Laptop · CPU only"
        title="THE PAYMENT FORMAT."
        aside="Standard is the useful baseline. Hiding is the real payment format—the one that protects amounts, keys, and randomness."
      />
      <div
        style={{
          marginTop: 45,
          border: `1px solid ${colors.line}`,
          borderRadius: 26,
          background: 'rgba(17,11,29,.78)',
          overflow: 'hidden',
          padding: '0 30px',
        }}
      >
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: '160px 1fr 1fr',
            gap: 22,
            padding: '22px 0 12px',
            color: colors.muted,
            fontFamily: fonts.mono,
            fontSize: 16,
            letterSpacing: 2,
          }}
        >
          <div>METRIC</div>
          <div style={{color: colors.shielded}}>STANDARD</div>
          <div style={{color: ACCENT}}>HIDING · ZERO-KNOWLEDGE</div>
        </div>
        {laptopMetrics.map((metric, index) => (
          <MetricBars key={metric.label} metric={metric} index={index} />
        ))}
      </div>
      <Reveal
        delay={170}
        style={{
          marginTop: 22,
          color: colors.muted,
          fontFamily: fonts.mono,
          fontSize: 16,
          letterSpacing: 1.5,
        }}
      >
        ONE CONFIGURATION PER PROCESS · WARMED RUNS · PEAK MEMORY ISOLATED
      </Reveal>
    </AbsoluteFill>
  );
};

const Phone: React.FC<{
  name: string;
  chip: string;
  prove: string;
  verify: string;
  peak: string;
  share: string;
  delay: number;
  color: string;
}> = ({name, chip, prove, verify, peak, share, delay, color}) => {
  const frame = useCurrentFrame();
  const {fps} = useVideoConfig();
  const p = enter(frame, fps, delay, 32);
  return (
    <div
      style={{
        opacity: p,
        transform: `translateY(${(1 - p) * 52}px)`,
        border: `1px solid ${color}66`,
        borderRadius: 30,
        padding: 34,
        background: `linear-gradient(145deg, ${color}12, ${colors.panel})`,
        boxShadow: `0 0 42px ${color}18`,
      }}
    >
      <div style={{display: 'flex', alignItems: 'center', gap: 24}}>
        <div
          style={{
            width: 96,
            height: 166,
            border: `3px solid ${color}`,
            borderRadius: 24,
            position: 'relative',
            boxShadow: `0 0 28px ${color}30`,
          }}
        >
          <div
            style={{
              position: 'absolute',
              top: 8,
              left: 31,
              width: 30,
              height: 7,
              borderRadius: 8,
              background: color,
            }}
          />
        </div>
        <div>
          <div
            style={{
              color: colors.ink,
              fontFamily: fonts.display,
              fontSize: 38,
              fontWeight: 900,
            }}
          >
            {name}
          </div>
          <div
            style={{
              color,
              fontFamily: fonts.mono,
              fontSize: 17,
              fontWeight: 900,
              letterSpacing: 2,
              marginTop: 9,
            }}
          >
            {chip}
          </div>
        </div>
      </div>
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: '1fr 1fr',
          gap: 18,
          marginTop: 34,
        }}
      >
        {[
          ['PROVE', prove],
          ['VERIFY', verify],
          ['PROCESS PEAK', peak],
          ['PROVER SHARE', share],
        ].map(([label, value]) => (
          <div
            key={label}
            style={{
              padding: 20,
              borderRadius: 18,
              background: `${color}0B`,
              border: `1px solid ${color}32`,
            }}
          >
            <div
              style={{
                color: colors.muted,
                fontFamily: fonts.mono,
                fontSize: 14,
                letterSpacing: 1.5,
              }}
            >
              {label}
            </div>
            <div
              style={{
                color: label === 'PROVE' ? color : colors.ink,
                fontFamily: fonts.display,
                fontSize: 27,
                fontWeight: 900,
                marginTop: 8,
              }}
            >
              {value}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

const PhoneScene: React.FC = () => {
  const frame = useCurrentFrame();
  return (
    <AbsoluteFill
      style={{
        opacity: sceneOpacity(frame, 300),
        padding: '135px 90px 90px',
      }}
    >
      <BenchTitle
        kicker="03 / Two physical iPhones"
        title={'THE WITNESS\nSTAYS ON DEVICE.'}
        aside="The cheap phone is only about 1.15× slower. The prover’s actual memory share differs by just 2 MB."
      />
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: '1fr 1fr',
          gap: 30,
          marginTop: 42,
        }}
      >
        <Phone
          name="iPhone 17 Pro Max"
          chip="A19 PRO · IOS 26.5.2"
          prove="0.284–0.314 s"
          verify="1.6–1.7 ms"
          peak="279 MB"
          share="259 MB"
          delay={20}
          color={ACCENT}
        />
        <Phone
          name="iPhone 16e"
          chip="A18 · IOS 26.2.1"
          prove="0.331–0.354 s"
          verify="1.8–2.0 ms"
          peak="304 MB"
          share="261 MB"
          delay={40}
          color={colors.shielded}
        />
      </div>
      <Reveal
        delay={155}
        style={{
          marginTop: 22,
          color: colors.ink,
          fontFamily: fonts.body,
          fontSize: 22,
          textAlign: 'center',
        }}
      >
        Proof sizes are byte-identical to the laptop build: 208.0 KB.
      </Reveal>
    </AbsoluteFill>
  );
};

const PrivacyPriceScene: React.FC = () => {
  const frame = useCurrentFrame();
  const {fps} = useVideoConfig();
  const left = enter(frame, fps, 18, 32);
  const right = enter(frame, fps, 42, 32);
  return (
    <AbsoluteFill
      style={{
        opacity: sceneOpacity(frame, 180),
        padding: '150px 110px 100px',
      }}
    >
      <BenchTitle
        kicker="04 / Privacy, priced"
        title="HIDING IS NOT FREE."
      />
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: '1fr 1fr',
          gap: 32,
          marginTop: 65,
        }}
      >
        {[
          {p: left, value: '2.8×', label: 'PROVE TIME'},
          {p: right, value: '1.3×', label: 'PROOF SIZE'},
        ].map((item) => (
          <div
            key={item.label}
            style={{
              opacity: item.p,
              transform: `scale(${0.9 + item.p * 0.1})`,
              height: 350,
              border: `1px solid ${ACCENT}66`,
              borderRadius: 30,
              background: `linear-gradient(145deg, ${ACCENT}14, ${colors.panel})`,
              display: 'grid',
              placeItems: 'center',
              textAlign: 'center',
            }}
          >
            <div>
              <div
                style={{
                  color: ACCENT,
                  fontFamily: fonts.display,
                  fontSize: 126,
                  fontWeight: 900,
                  letterSpacing: -7,
                }}
              >
                {item.value}
              </div>
              <div
                style={{
                  color: colors.muted,
                  fontFamily: fonts.mono,
                  fontSize: 19,
                  fontWeight: 900,
                  letterSpacing: 3,
                }}
              >
                {item.label}
              </div>
            </div>
          </div>
        ))}
      </div>
      <Reveal
        delay={98}
        style={{
          marginTop: 33,
          textAlign: 'center',
          color: colors.ink,
          fontFamily: fonts.body,
          fontSize: 24,
        }}
      >
        The decision: hiding is the payment format—and the only one.
      </Reveal>
    </AbsoluteFill>
  );
};

const BenchFinale: React.FC = () => {
  const frame = useCurrentFrame();
  const {fps} = useVideoConfig();
  const p = enter(frame, fps, 10, 38);
  const sweep = interpolate(frame, [10, 185], [-0.2, 1.2], clamp);
  return (
    <AbsoluteFill
      style={{
        opacity: sceneOpacity(frame, 240),
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
          background: `linear-gradient(90deg, transparent, ${ACCENT}24, transparent)`,
        }}
      />
      <div
        style={{
          position: 'absolute',
          width: 1140,
          height: 1140,
          borderRadius: '50%',
          border: `1px solid ${ACCENT}38`,
          boxShadow: `inset 0 0 150px ${ACCENT}15`,
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
          <ProtocolMark short="UV" color={ACCENT} size={112} active />
        </div>
        <Kicker color={ACCENT}>Measured, not projected</Kicker>
        <div
          style={{
            color: colors.ink,
            fontFamily: fonts.display,
            fontSize: 90,
            lineHeight: 0.98,
            fontWeight: 900,
            letterSpacing: -5,
          }}
        >
          A PRIVATE PROOF
          <br />
          IN ABOUT
          <span style={{color: ACCENT}}> 0.3 SECONDS.</span>
        </div>
        <div
          style={{
            color: colors.muted,
            fontFamily: fonts.body,
            fontSize: 26,
            marginTop: 28,
          }}
        >
          Fast enough that a self-custodial phone never sends its payment
          secrets to a prover.
        </div>
        <div
          style={{
            display: 'inline-flex',
            marginTop: 35,
            padding: '14px 22px',
            borderRadius: 999,
            border: `1px solid ${ACCENT}66`,
            color: ACCENT,
            fontFamily: fonts.mono,
            fontSize: 16,
            letterSpacing: 2,
          }}
        >
          ULTRAVIENET.GITHUB.IO/ULTRAVIOLET/BENCHMARKS.HTML
        </div>
        <div
          style={{
            color: colors.muted,
            fontFamily: fonts.mono,
            fontSize: 14,
            letterSpacing: 1.5,
            marginTop: 22,
          }}
        >
          REPRODUCIBLE FROM SOURCE · RESEARCH PROJECT · UNAUDITED
        </div>
      </div>
    </AbsoluteFill>
  );
};

export const UltravioletBenchmarks: React.FC = () => {
  return (
    <AbsoluteFill
      style={{
        background: colors.bg,
        color: colors.ink,
        fontFamily: fonts.body,
      }}
    >
      <NoiseGrid accent={ACCENT} />
      <Sequence from={0} durationInFrames={180}>
        <BenchIntro />
      </Sequence>
      <Sequence from={180} durationInFrames={300}>
        <CircuitScene />
      </Sequence>
      <Sequence from={480} durationInFrames={300}>
        <LaptopScene />
      </Sequence>
      <Sequence from={780} durationInFrames={300}>
        <PhoneScene />
      </Sequence>
      <Sequence from={1080} durationInFrames={180}>
        <PrivacyPriceScene />
      </Sequence>
      <Sequence from={1260} durationInFrames={240}>
        <BenchFinale />
      </Sequence>
      <SeriesChrome
        label="ULTRAVIOLET / BENCHMARK NOTES 01"
        accent={ACCENT}
      />
    </AbsoluteFill>
  );
};
