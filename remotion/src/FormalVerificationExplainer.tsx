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
  Reveal,
  sceneOpacity,
  SeriesChrome,
} from './components';
import {colors, fonts} from './theme';

const ACCENT = '#70E6C1';
const WARNING = '#FF6688';
const AMBER = '#FFBD69';

const Scene: React.FC<{
  duration: number;
  children: React.ReactNode;
  padding?: string;
}> = ({duration, children, padding = '135px 100px 90px'}) => {
  const frame = useCurrentFrame();
  return (
    <AbsoluteFill
      style={{
        opacity: sceneOpacity(frame, duration, 22),
        padding,
      }}
    >
      {children}
    </AbsoluteFill>
  );
};

const SceneTitle: React.FC<{
  kicker: string;
  title: string;
  aside?: string;
  color?: string;
}> = ({kicker, title, aside, color = ACCENT}) => (
  <Reveal>
    <Kicker color={color}>{kicker}</Kicker>
    <div
      style={{
        display: 'flex',
        alignItems: 'flex-end',
        justifyContent: 'space-between',
        gap: 70,
      }}
    >
      <div
        style={{
          maxWidth: aside ? 1120 : 1550,
          color: colors.ink,
          fontFamily: fonts.display,
          fontSize: 69,
          fontWeight: 900,
          letterSpacing: -3.5,
          lineHeight: 0.98,
          whiteSpace: 'pre-line',
        }}
      >
        {title}
      </div>
      {aside ? (
        <div
          style={{
            maxWidth: 510,
            color: colors.muted,
            fontFamily: fonts.body,
            fontSize: 23,
            lineHeight: 1.42,
          }}
        >
          {aside}
        </div>
      ) : null}
    </div>
  </Reveal>
);

const Chip: React.FC<{
  children: React.ReactNode;
  color?: string;
}> = ({children, color = ACCENT}) => (
  <span
    style={{
      display: 'inline-flex',
      alignItems: 'center',
      padding: '8px 13px',
      border: `1px solid ${color}70`,
      borderRadius: 999,
      color,
      background: `${color}10`,
      fontFamily: fonts.mono,
      fontSize: 14,
      fontWeight: 800,
      letterSpacing: 1.3,
      whiteSpace: 'nowrap',
    }}
  >
    {children}
  </span>
);

const ColdOpen: React.FC = () => {
  const frame = useCurrentFrame();
  const {fps} = useVideoConfig();
  const p = enter(frame, fps, 12, 38);
  const ring = interpolate(frame, [18, 135], [0, 1], {
    ...clamp,
    easing: Easing.out(Easing.cubic),
  });
  const fracture = interpolate(frame, [108, 155], [0, 1], clamp);

  return (
    <Scene duration={210} padding="140px 110px 95px">
      <div
        style={{
          position: 'absolute',
          right: 100,
          top: 165,
          width: 660,
          height: 660,
          borderRadius: '50%',
          border: `2px solid ${ACCENT}55`,
          transform: `scale(${0.75 + ring * 0.25})`,
          opacity: ring,
          boxShadow: `inset 0 0 120px ${ACCENT}16, 0 0 90px ${ACCENT}12`,
        }}
      >
        <div
          style={{
            position: 'absolute',
            left: 168,
            top: 260,
            width: 145,
            height: 34,
            borderRadius: 22,
            background: ACCENT,
            transform: 'rotate(44deg)',
            transformOrigin: 'right center',
            boxShadow: `0 0 35px ${ACCENT}66`,
          }}
        />
        <div
          style={{
            position: 'absolute',
            left: 287,
            top: 190,
            width: 260,
            height: 34,
            borderRadius: 22,
            background: ACCENT,
            transform: 'rotate(-48deg)',
            transformOrigin: 'left center',
            boxShadow: `0 0 35px ${ACCENT}66`,
          }}
        />
        {[
          {left: 300, top: 250, width: 190, rotate: 18},
          {left: 348, top: 302, width: 145, rotate: 72},
          {left: 255, top: 328, width: 125, rotate: 135},
        ].map((line, index) => (
          <div
            key={index}
            style={{
              position: 'absolute',
              left: line.left,
              top: line.top,
              width: line.width * fracture,
              height: 2,
              background: WARNING,
              transform: `rotate(${line.rotate}deg)`,
              transformOrigin: 'left',
              boxShadow: `0 0 12px ${WARNING}`,
            }}
          />
        ))}
      </div>

      <div style={{position: 'relative', zIndex: 2, maxWidth: 1110}}>
        <Reveal delay={4}>
          <Kicker color={ACCENT}>FIELD NOTE 06 / FORMAL VERIFICATION</Kicker>
        </Reveal>
        <div
          style={{
            opacity: p,
            color: colors.ink,
            fontFamily: fonts.display,
            fontSize: 107,
            fontWeight: 900,
            letterSpacing: -6,
            lineHeight: 0.9,
          }}
        >
          A GREEN CHECK
          <br />
          IS NOT <span style={{color: WARNING}}>TRUTH.</span>
        </div>
        <Reveal delay={62} style={{maxWidth: 870, marginTop: 36}}>
          <div
            style={{
              color: colors.muted,
              fontFamily: fonts.body,
              fontSize: 27,
              lineHeight: 1.42,
            }}
          >
            It means one claim survived one model, under named assumptions,
            inside one toolchain.
          </div>
        </Reveal>
        <Reveal delay={105} style={{marginTop: 34}}>
          <Chip color={WARNING}>VERIFIED* &nbsp; *READ THE TRUST BOUNDARY</Chip>
        </Reveal>
      </div>
    </Scene>
  );
};

const pipelineSteps = [
  {label: 'CLAIM', detail: 'nothing bad happens'},
  {label: 'STATE MODEL', detail: 'turn behavior into transitions'},
  {label: 'ADVERSARY', detail: 'decide what they control'},
  {label: 'INVARIANT', detail: 'make failure executable'},
  {label: 'CHECKER', detail: 'search every allowed path'},
];

const Pipeline: React.FC = () => {
  const frame = useCurrentFrame();
  const travel = interpolate(frame, [45, 220], [0, 1], clamp);

  return (
    <Scene duration={360}>
      <SceneTitle
        kicker="HOW IT WORKS"
        title={'MAKE THE QUESTION\nEXECUTABLE.'}
        aside="Formal methods do not prove a paragraph. They prove a precisely encoded property of a precisely encoded system."
      />

      <div
        style={{
          position: 'relative',
          display: 'grid',
          gridTemplateColumns: 'repeat(5, 1fr)',
          gap: 20,
          marginTop: 68,
        }}
      >
        <div
          style={{
            position: 'absolute',
            left: 90,
            right: 90,
            top: 50,
            height: 3,
            background: colors.line,
          }}
        >
          <div
            style={{
              width: `${travel * 100}%`,
              height: '100%',
              background: `linear-gradient(90deg, ${ACCENT}, ${colors.uv})`,
              boxShadow: `0 0 14px ${ACCENT}`,
            }}
          />
        </div>
        {pipelineSteps.map((step, index) => (
          <Reveal key={step.label} delay={25 + index * 20}>
            <div
              style={{
                position: 'relative',
                minHeight: 160,
                padding: '28px 22px 20px',
                border: `1px solid ${index === 4 ? ACCENT : colors.line}`,
                borderRadius: 20,
                background: colors.bgRaised,
                textAlign: 'center',
              }}
            >
              <div
                style={{
                  position: 'relative',
                  zIndex: 2,
                  width: 48,
                  height: 48,
                  margin: '0 auto 21px',
                  display: 'grid',
                  placeItems: 'center',
                  borderRadius: '50%',
                  background: index === 4 ? ACCENT : colors.panel2,
                  border: `2px solid ${index === 4 ? ACCENT : colors.uv}`,
                  color: index === 4 ? colors.bg : colors.uvBright,
                  fontFamily: fonts.mono,
                  fontSize: 15,
                  fontWeight: 900,
                  boxShadow: index === 4 ? `0 0 25px ${ACCENT}55` : 'none',
                }}
              >
                {String(index + 1).padStart(2, '0')}
              </div>
              <div
                style={{
                  color: colors.ink,
                  fontFamily: fonts.mono,
                  fontSize: 17,
                  fontWeight: 900,
                  letterSpacing: 1.6,
                }}
              >
                {step.label}
              </div>
              <div
                style={{
                  marginTop: 10,
                  color: colors.muted,
                  fontFamily: fonts.body,
                  fontSize: 17,
                  lineHeight: 1.3,
                }}
              >
                {step.detail}
              </div>
            </div>
          </Reveal>
        ))}
      </div>

      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(3, 1fr)',
          gap: 20,
          marginTop: 28,
        }}
      >
        {[
          ['QUINT + APALACHE', 'protocol state space', 'BOUNDED + INDUCTIVE'],
          ['ITF TRACE REPLAY', 'model meets real Rust', 'CONFORMANCE'],
          ['KANI', 'selected production functions', 'EVERY INPUT'],
        ].map(([name, detail, badge], index) => (
          <Reveal key={name} delay={145 + index * 18}>
            <div
              style={{
                display: 'flex',
                minHeight: 88,
                padding: '18px 20px',
                alignItems: 'center',
                justifyContent: 'space-between',
                gap: 18,
                border: `1px solid ${ACCENT}35`,
                borderRadius: 16,
                background: `${ACCENT}08`,
              }}
            >
              <div>
                <div
                  style={{
                    color: ACCENT,
                    fontFamily: fonts.mono,
                    fontSize: 16,
                    fontWeight: 900,
                    letterSpacing: 1.3,
                  }}
                >
                  {name}
                </div>
                <div
                  style={{
                    marginTop: 6,
                    color: colors.muted,
                    fontFamily: fonts.body,
                    fontSize: 17,
                  }}
                >
                  {detail}
                </div>
              </div>
              <Chip>{badge}</Chip>
            </div>
          </Reveal>
        ))}
      </div>
    </Scene>
  );
};

const checked = [
  ['AUTHORIZATION', 'Only the anchor-preimage holder spends'],
  ['CONSERVATION', 'Value cannot inflate across a lineage'],
  ['SETTLEMENT', 'Every ancestor won its Bitcoin race'],
  ['ISSUANCE', 'Per-asset supply is exact and visible'],
  ['REORGS', 'Invalid coins quarantine; valid ones restore'],
  ['LIVENESS', 'Honest payments remain possible'],
];

const outside = [
  ['CRYPTOGRAPHY', 'Hashes and the STARK are assumed sound'],
  ['PRIVACY', 'PCS hiding is not formally proved here'],
  ['CONFORMANCE', 'Not every model/code tie is automatic'],
  ['TOOLCHAIN', 'The checker may itself contain bugs'],
];

const Scope: React.FC = () => {
  return (
    <Scene duration={360}>
      <SceneTitle
        kicker="THE ULTRAVIOLET CLAIM"
        title="PROVE THE MONEY RULES."
        aside="Seven protocol models ask who may spend, whether supply composes, and whether hostile scheduling can destroy value."
      />

      <div
        style={{
          display: 'grid',
          gridTemplateColumns: '1.45fr .8fr',
          gap: 28,
          marginTop: 58,
        }}
      >
        <Reveal delay={25}>
          <div
            style={{
              padding: 25,
              border: `1px solid ${ACCENT}55`,
              borderRadius: 22,
              background: `${ACCENT}08`,
            }}
          >
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                marginBottom: 18,
              }}
            >
              <Chip>CHECKED</Chip>
              <span
                style={{
                  color: colors.muted,
                  fontFamily: fonts.mono,
                  fontSize: 13,
                  letterSpacing: 1.4,
                }}
              >
                PROTOCOL SAFETY + LIVENESS
              </span>
            </div>
            <div
              style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(2, 1fr)',
                gap: 12,
              }}
            >
              {checked.map(([name, detail], index) => (
                <Reveal key={name} delay={45 + index * 12}>
                  <div
                    style={{
                      minHeight: 89,
                      padding: '16px 17px',
                      borderRadius: 14,
                      background: colors.bgRaised,
                      border: `1px solid ${colors.line}`,
                    }}
                  >
                    <div
                      style={{
                        color: ACCENT,
                        fontFamily: fonts.mono,
                        fontSize: 14,
                        fontWeight: 900,
                        letterSpacing: 1.2,
                      }}
                    >
                      ✓ {name}
                    </div>
                    <div
                      style={{
                        marginTop: 7,
                        color: colors.ink,
                        fontFamily: fonts.body,
                        fontSize: 17,
                        lineHeight: 1.28,
                      }}
                    >
                      {detail}
                    </div>
                  </div>
                </Reveal>
              ))}
            </div>
          </div>
        </Reveal>

        <Reveal delay={55}>
          <div
            style={{
              height: '100%',
              padding: 25,
              border: `1px solid ${WARNING}55`,
              borderRadius: 22,
              background: `${WARNING}08`,
            }}
          >
            <div style={{marginBottom: 18}}>
              <Chip color={WARNING}>ASSUMED / OUTSIDE</Chip>
            </div>
            <div style={{display: 'grid', gap: 11}}>
              {outside.map(([name, detail], index) => (
                <Reveal key={name} delay={80 + index * 13}>
                  <div
                    style={{
                      padding: '13px 15px',
                      borderRadius: 13,
                      background: colors.bgRaised,
                      border: `1px solid ${colors.line}`,
                    }}
                  >
                    <div
                      style={{
                        color: WARNING,
                        fontFamily: fonts.mono,
                        fontSize: 13,
                        fontWeight: 900,
                        letterSpacing: 1.1,
                      }}
                    >
                      ? {name}
                    </div>
                    <div
                      style={{
                        marginTop: 6,
                        color: colors.muted,
                        fontFamily: fonts.body,
                        fontSize: 16,
                        lineHeight: 1.25,
                      }}
                    >
                      {detail}
                    </div>
                  </div>
                </Reveal>
              ))}
            </div>
          </div>
        </Reveal>
      </div>

      <Reveal delay={185} style={{marginTop: 26, textAlign: 'center'}}>
        <div
          style={{
            color: colors.ink,
            fontFamily: fonts.display,
            fontSize: 27,
            fontWeight: 900,
            letterSpacing: -0.8,
          }}
        >
          THE MODEL CATCHES THE BUG YOU WROTE DOWN.{' '}
          <span style={{color: WARNING}}>THE BOUNDARY DECIDES WHICH BUGS EXIST.</span>
        </div>
      </Reveal>
    </Scene>
  );
};

const events = [
  {
    date: 'JUL 25',
    title: 'AI-ASSISTED “DISPROOF”',
    detail: 'A two-commit Lean repo claims a non-terminating Collatz orbit.',
    color: AMBER,
  },
  {
    date: 'JUL 26',
    title: 'CHECKER BUGS LAND',
    detail: 'Kernel Arena PRs 81–83 record distinct soundness failures.',
    color: colors.taproot,
  },
  {
    date: 'JUL 28',
    title: 'THE PROOF IS THE REPRO',
    detail: 'Lean #14576 traces an axiom-free False back to the artifact.',
    color: WARNING,
  },
  {
    date: 'JUL 28',
    title: 'TWO CHECKERS. TWO BUGS.',
    detail: 'Official Lean and old Nanoda accepted through different gaps.',
    color: colors.rgb,
  },
];

const Timeline: React.FC = () => {
  const frame = useCurrentFrame();
  const line = interpolate(frame, [35, 250], [0, 1], {
    ...clamp,
    easing: Easing.out(Easing.cubic),
  });
  const split = enter(frame, 30, 300, 34);

  return (
    <Scene duration={600} padding="125px 95px 90px">
      <SceneTitle
        kicker="THE MOST AI TIMELINE POSSIBLE"
        title="COLLATZ REMAINS UNSOLVED."
        aside="The artifact verified. The conclusion did not survive inspection of the verifier."
        color={WARNING}
      />

      <div
        style={{
          position: 'relative',
          display: 'grid',
          gridTemplateColumns: 'repeat(4, 1fr)',
          gap: 18,
          marginTop: 55,
        }}
      >
        <div
          style={{
            position: 'absolute',
            left: 70,
            right: 70,
            top: 35,
            height: 3,
            background: colors.line,
          }}
        >
          <div
            style={{
              width: `${line * 100}%`,
              height: '100%',
              background: `linear-gradient(90deg, ${AMBER}, ${WARNING})`,
              boxShadow: `0 0 14px ${WARNING}77`,
            }}
          />
        </div>
        {events.map((event, index) => (
          <Reveal key={`${event.date}-${event.title}`} delay={30 + index * 38}>
            <div>
              <div
                style={{
                  position: 'relative',
                  zIndex: 2,
                  width: 72,
                  height: 72,
                  display: 'grid',
                  placeItems: 'center',
                  margin: '0 auto 24px',
                  borderRadius: '50%',
                  background: colors.bgRaised,
                  border: `2px solid ${event.color}`,
                  color: event.color,
                  fontFamily: fonts.mono,
                  fontSize: 14,
                  fontWeight: 900,
                  boxShadow: `0 0 24px ${event.color}38`,
                }}
              >
                {event.date}
              </div>
              <div
                style={{
                  minHeight: 150,
                  padding: '20px 20px',
                  border: `1px solid ${event.color}48`,
                  borderRadius: 17,
                  background: colors.bgRaised,
                }}
              >
                <div
                  style={{
                    color: event.color,
                    fontFamily: fonts.mono,
                    fontSize: 16,
                    fontWeight: 900,
                    letterSpacing: 1.2,
                    lineHeight: 1.2,
                  }}
                >
                  {event.title}
                </div>
                <div
                  style={{
                    marginTop: 13,
                    color: colors.muted,
                    fontFamily: fonts.body,
                    fontSize: 18,
                    lineHeight: 1.32,
                  }}
                >
                  {event.detail}
                </div>
              </div>
            </div>
          </Reveal>
        ))}
      </div>

      <div
        style={{
          opacity: split,
          transform: `translateY(${(1 - split) * 24}px)`,
          display: 'grid',
          gridTemplateColumns: '1fr 1fr .9fr',
          gap: 18,
          marginTop: 30,
        }}
      >
        {[
          {
            name: 'OFFICIAL LEAN',
            status: 'PASS',
            detail: 'Nested-inductive path omitted a required type check.',
            color: WARNING,
          },
          {
            name: 'OLDER NANODA',
            status: 'PASS',
            detail: 'A different incomplete check accepted the crafted expression.',
            color: colors.rgb,
          },
          {
            name: 'MATHEMATICS',
            status: 'NO',
            detail: 'No Collatz disproof. The shared “proof” was the exploit surface.',
            color: colors.muted,
          },
        ].map((lane) => (
          <div
            key={lane.name}
            style={{
              display: 'grid',
              minHeight: 112,
              padding: '18px 20px',
              alignItems: 'center',
              gridTemplateColumns: '1fr auto',
              gap: 15,
              border: `1px solid ${lane.color}45`,
              borderRadius: 16,
              background: `${lane.color}08`,
            }}
          >
            <div>
              <div
                style={{
                  color: lane.color,
                  fontFamily: fonts.mono,
                  fontSize: 15,
                  fontWeight: 900,
                  letterSpacing: 1.3,
                }}
              >
                {lane.name}
              </div>
              <div
                style={{
                  marginTop: 8,
                  color: colors.muted,
                  fontFamily: fonts.body,
                  fontSize: 16,
                  lineHeight: 1.28,
                }}
              >
                {lane.detail}
              </div>
            </div>
            <div
              style={{
                minWidth: 76,
                padding: '10px 12px',
                borderRadius: 12,
                background: lane.status === 'PASS' ? lane.color : colors.panel2,
                color: lane.status === 'PASS' ? colors.bg : colors.ink,
                fontFamily: fonts.mono,
                fontSize: 18,
                fontWeight: 900,
                textAlign: 'center',
              }}
            >
              {lane.status}
            </div>
          </div>
        ))}
      </div>

      <Reveal delay={430} style={{marginTop: 19, textAlign: 'center'}}>
        <div
          style={{
            color: colors.muted,
            fontFamily: fonts.mono,
            fontSize: 13,
            letterSpacing: 1.1,
          }}
        >
          SOURCES: XRCHZ/COLLATZLEAN · LEAN-KERNEL-ARENA #81–83 · LEAN4 #14576
        </div>
      </Reveal>
    </Scene>
  );
};

const AiTrap: React.FC = () => {
  const frame = useCurrentFrame();
  const progress = interpolate(frame, [65, 210], [0, 1], {
    ...clamp,
    easing: Easing.inOut(Easing.cubic),
  });
  const x = interpolate(progress, [0, 0.34, 0.56, 0.76, 1], [0, 0.34, 0.48, 0.72, 1]);
  const y = interpolate(progress, [0, 0.34, 0.56, 0.76, 1], [0.5, 0.5, 0.82, 0.82, 0.5]);

  return (
    <Scene duration={360}>
      <SceneTitle
        kicker="THE AI PROBLEM"
        title="OPTIMIZATION IS NOT UNDERSTANDING."
        aside="An LLM can discover a route to acceptance without knowing that the route passes through a bug."
        color={WARNING}
      />

      <div
        style={{
          position: 'relative',
          height: 330,
          marginTop: 55,
          border: `1px solid ${colors.line}`,
          borderRadius: 24,
          background: colors.bgRaised,
          overflow: 'hidden',
        }}
      >
        <div
          style={{
            position: 'absolute',
            left: 42,
            top: 115,
            width: 310,
            padding: '19px 22px',
            border: `1px solid ${colors.uv}66`,
            borderRadius: 16,
            background: colors.panel,
          }}
        >
          <div
            style={{
              color: colors.uvBright,
              fontFamily: fonts.mono,
              fontSize: 13,
              fontWeight: 900,
              letterSpacing: 1.4,
            }}
          >
            PROMPT
          </div>
          <div
            style={{
              marginTop: 10,
              color: colors.ink,
              fontFamily: fonts.display,
              fontSize: 24,
              fontWeight: 900,
            }}
          >
            MAKE THE CHECKER SAY ✓
          </div>
        </div>

        <div
          style={{
            position: 'absolute',
            left: 390,
            right: 380,
            top: 164,
            height: 3,
            background: colors.line,
          }}
        />
        <div
          style={{
            position: 'absolute',
            left: 620,
            top: 160,
            width: 230,
            height: 125,
            borderLeft: `3px solid ${WARNING}`,
            borderBottom: `3px solid ${WARNING}`,
            borderRadius: '0 0 0 24px',
            opacity: progress > 0.38 ? 1 : 0,
          }}
        />
        <div
          style={{
            position: 'absolute',
            left: 675,
            top: 250,
            padding: '12px 16px',
            border: `1px solid ${WARNING}88`,
            borderRadius: 12,
            background: `${WARNING}12`,
            color: WARNING,
            fontFamily: fonts.mono,
            fontSize: 14,
            fontWeight: 900,
            letterSpacing: 1.2,
          }}
        >
          BUG-SHAPED WORMHOLE
        </div>
        <div
          style={{
            position: 'absolute',
            left: 390 + x * 1050,
            top: 164 + (y - 0.5) * 235,
            width: 18,
            height: 18,
            borderRadius: '50%',
            background: colors.uvBright,
            boxShadow: `0 0 25px ${colors.uvBright}`,
          }}
        />

        <div
          style={{
            position: 'absolute',
            right: 42,
            top: 103,
            width: 300,
            height: 124,
            display: 'grid',
            placeItems: 'center',
            border: `2px solid ${ACCENT}`,
            borderRadius: 18,
            background: `${ACCENT}10`,
            color: ACCENT,
            fontFamily: fonts.display,
            fontSize: 37,
            fontWeight: 900,
            boxShadow: `0 0 35px ${ACCENT}22`,
          }}
        >
          ✓ ACCEPTED
        </div>
      </div>

      <Reveal delay={210} style={{marginTop: 25}}>
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            gap: 35,
          }}
        >
          <div
            style={{
              color: colors.ink,
              fontFamily: fonts.display,
              fontSize: 27,
              fontWeight: 900,
            }}
          >
            THE MODEL FOUND A PATH.{' '}
            <span style={{color: WARNING}}>IT DID NOT FIND THE TRUTH.</span>
          </div>
          <Chip color={AMBER}>AUTHOR CONFIRMED LLM(S) WERE INVOLVED</Chip>
        </div>
      </Reveal>
    </Scene>
  );
};

const Finale: React.FC = () => {
  const frame = useCurrentFrame();
  const {fps} = useVideoConfig();
  const p = enter(frame, fps, 10, 40);
  const glow = 0.7 + Math.sin(frame / 18) * 0.15;

  return (
    <Scene duration={360} padding="135px 110px 90px">
      <div
        style={{
          position: 'absolute',
          left: '50%',
          top: '48%',
          width: 940,
          height: 940,
          borderRadius: '50%',
          border: `1px solid ${ACCENT}30`,
          transform: `translate(-50%, -50%) scale(${glow})`,
          boxShadow: `inset 0 0 150px ${ACCENT}10`,
        }}
      />
      <div
        style={{
          position: 'relative',
          zIndex: 2,
          opacity: p,
          margin: 'auto',
          maxWidth: 1590,
          textAlign: 'center',
        }}
      >
        <Kicker color={ACCENT}>THE ONLY HONEST CONCLUSION</Kicker>
        <div
          style={{
            color: colors.ink,
            fontFamily: fonts.display,
            fontSize: 88,
            fontWeight: 900,
            lineHeight: 0.94,
            letterSpacing: -5,
          }}
        >
          USE AI TO <span style={{color: ACCENT}}>SEARCH.</span>
          <br />
          NEVER LET IT OWN THE <span style={{color: WARNING}}>CLAIM.</span>
        </div>

        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(3, 1fr)',
            gap: 18,
            marginTop: 50,
          }}
        >
          {[
            ['01', 'HUMANS DEFINE', 'the property and adversary'],
            ['02', 'CODE MUST MEET MODEL', 'through replay or direct proof'],
            ['03', 'TOOLS ARE IN SCOPE', 'the verifier is part of the threat model'],
          ].map(([number, title, detail], index) => (
            <Reveal key={number} delay={70 + index * 18}>
              <div
                style={{
                  minHeight: 105,
                  padding: '20px 22px',
                  border: `1px solid ${ACCENT}3D`,
                  borderRadius: 16,
                  background: colors.bgRaised,
                  textAlign: 'left',
                }}
              >
                <div style={{display: 'flex', alignItems: 'center', gap: 15}}>
                  <span
                    style={{
                      color: ACCENT,
                      fontFamily: fonts.mono,
                      fontSize: 14,
                      fontWeight: 900,
                    }}
                  >
                    {number}
                  </span>
                  <span
                    style={{
                      color: colors.ink,
                      fontFamily: fonts.mono,
                      fontSize: 16,
                      fontWeight: 900,
                      letterSpacing: 1.2,
                    }}
                  >
                    {title}
                  </span>
                </div>
                <div
                  style={{
                    marginTop: 12,
                    color: colors.muted,
                    fontFamily: fonts.body,
                    fontSize: 18,
                  }}
                >
                  {detail}
                </div>
              </div>
            </Reveal>
          ))}
        </div>

        <Reveal delay={145} style={{marginTop: 34}}>
          <div
            style={{
              color: colors.muted,
              fontFamily: fonts.mono,
              fontSize: 15,
              letterSpacing: 2,
            }}
          >
            YES, INCLUDING THE AI THAT MADE THIS FILM.
          </div>
        </Reveal>
      </div>
    </Scene>
  );
};

export const FormalVerificationExplainer: React.FC = () => {
  return (
    <AbsoluteFill style={{background: colors.bg}}>
      <NoiseGrid accent={ACCENT} />
      <Sequence from={0} durationInFrames={210}>
        <ColdOpen />
      </Sequence>
      <Sequence from={210} durationInFrames={360}>
        <Pipeline />
      </Sequence>
      <Sequence from={570} durationInFrames={360}>
        <Scope />
      </Sequence>
      <Sequence from={930} durationInFrames={600}>
        <Timeline />
      </Sequence>
      <Sequence from={1530} durationInFrames={360}>
        <AiTrap />
      </Sequence>
      <Sequence from={1890} durationInFrames={360}>
        <Finale />
      </Sequence>
      <SeriesChrome
        label="ULTRAVIOLET / FIELD NOTES 06"
        accent={ACCENT}
      />
    </AbsoluteFill>
  );
};
