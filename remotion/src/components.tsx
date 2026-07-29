import React from 'react';
import {
  AbsoluteFill,
  Easing,
  interpolate,
  spring,
  useCurrentFrame,
  useVideoConfig,
} from 'remotion';
import {colors, fonts} from './theme';

export const clamp = {
  extrapolateLeft: 'clamp' as const,
  extrapolateRight: 'clamp' as const,
};

export const enter = (
  frame: number,
  fps: number,
  delay = 0,
  durationInFrames = 28,
) => {
  return spring({
    frame: frame - delay,
    fps,
    durationInFrames,
    config: {damping: 18, stiffness: 120, mass: 0.8},
  });
};

export const fadeWindow = (
  frame: number,
  start: number,
  end: number,
  fade = 18,
) =>
  interpolate(
    frame,
    [start, start + fade, end - fade, end],
    [0, 1, 1, 0],
    clamp,
  );

export const NoiseGrid: React.FC<{accent?: string}> = ({
  accent = colors.uv,
}) => {
  const frame = useCurrentFrame();
  const fibers = Array.from({length: 42}, (_, index) => {
    const x = (index * 347 + 83) % 1920;
    const y = (index * 191 + 117) % 1080;
    const length = 28 + ((index * 31) % 104);
    const drift = Math.sin(frame / 38 + index * 1.7) * 9;
    const hue =
      index % 4 === 0
        ? accent
        : index % 4 === 1
          ? '#5C79FF'
          : index % 4 === 2
            ? '#32C6B0'
            : '#DF4F97';

    return (
      <div
        key={index}
        style={{
          position: 'absolute',
          left: x + drift,
          top: y,
          width: length,
          height: 1,
          opacity: 0.08 + (index % 5) * 0.018,
          transform: `rotate(${(index * 29) % 180}deg)`,
          transformOrigin: 'left center',
          background: `linear-gradient(90deg, transparent, ${hue}, transparent)`,
        }}
      />
    );
  });

  return (
    <AbsoluteFill
      style={{
        overflow: 'hidden',
        background: `radial-gradient(circle at 82% 13%, ${accent}20, transparent 34%), radial-gradient(circle at 12% 88%, rgba(35,92,130,.13), transparent 31%), #090611`,
      }}
    >
      <AbsoluteFill
        style={{
          opacity: 0.28,
          backgroundImage:
            'linear-gradient(rgba(255,255,255,.022) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,.022) 1px, transparent 1px)',
          backgroundSize: '64px 64px',
          transform: `translateY(${(frame * 0.08) % 64}px)`,
        }}
      />
      {fibers}
    </AbsoluteFill>
  );
};

export const GlobalChrome: React.FC = () => {
  return <SeriesChrome label="ULTRAVIOLET / FIELD NOTES 01" />;
};

export const SeriesChrome: React.FC<{
  label: string;
  accent?: string;
}> = ({label, accent = colors.uv}) => {
  const frame = useCurrentFrame();
  const {durationInFrames, fps} = useVideoConfig();
  const progress = frame / (durationInFrames - 1);
  const seconds = Math.floor(frame / fps);
  const totalSeconds = Math.ceil(durationInFrames / fps);

  return (
    <AbsoluteFill style={{pointerEvents: 'none', zIndex: 100}}>
      <div
        style={{
          position: 'absolute',
          left: 70,
          top: 45,
          display: 'flex',
          alignItems: 'center',
          gap: 16,
          color: colors.muted,
          fontFamily: fonts.mono,
          fontSize: 18,
          letterSpacing: 3,
        }}
      >
        <span
          style={{
            display: 'inline-block',
            width: 10,
            height: 10,
            borderRadius: 10,
            background: accent,
            boxShadow: `0 0 18px ${accent}`,
          }}
        />
        {label}
      </div>
      <div
        style={{
          position: 'absolute',
          right: 70,
          top: 45,
          color: colors.muted,
          fontFamily: fonts.mono,
          fontSize: 18,
          letterSpacing: 2,
        }}
      >
        {String(Math.floor(seconds / 60)).padStart(2, '0')}:
        {String(seconds % 60).padStart(2, '0')} /{' '}
        {String(Math.floor(totalSeconds / 60)).padStart(2, '0')}:
        {String(totalSeconds % 60).padStart(2, '0')}
      </div>
      <div
        style={{
          position: 'absolute',
          left: 70,
          right: 70,
          bottom: 42,
          height: 2,
          background: colors.line,
        }}
      >
        <div
          style={{
            width: `${progress * 100}%`,
            height: '100%',
            background: `linear-gradient(90deg, ${accent}88, ${accent})`,
            boxShadow: `0 0 12px ${accent}`,
          }}
        />
      </div>
    </AbsoluteFill>
  );
};

export const Kicker: React.FC<{
  children: React.ReactNode;
  color?: string;
}> = ({children, color = colors.uv}) => (
  <div
    style={{
      color,
      fontFamily: fonts.mono,
      fontWeight: 700,
      fontSize: 20,
      letterSpacing: 5,
      textTransform: 'uppercase',
      marginBottom: 20,
    }}
  >
    {children}
  </div>
);

export const Reveal: React.FC<{
  children: React.ReactNode;
  delay?: number;
  y?: number;
  style?: React.CSSProperties;
}> = ({children, delay = 0, y = 36, style}) => {
  const frame = useCurrentFrame();
  const {fps} = useVideoConfig();
  const p = enter(frame, fps, delay);
  return (
    <div
      style={{
        opacity: p,
        transform: `translateY(${(1 - p) * y}px)`,
        ...style,
      }}
    >
      {children}
    </div>
  );
};

export const ProtocolMark: React.FC<{
  short: string;
  color: string;
  size?: number;
  active?: boolean;
}> = ({short, color, size = 72, active = false}) => (
  <div
    style={{
      width: size,
      height: size,
      borderRadius: size * 0.26,
      display: 'grid',
      placeItems: 'center',
      flex: '0 0 auto',
      color,
      background: `${color}18`,
      border: `1px solid ${color}72`,
      boxShadow: active ? `0 0 36px ${color}55` : 'none',
      fontFamily: fonts.display,
      fontWeight: 900,
      fontSize: size * 0.3,
      letterSpacing: -1,
    }}
  >
    {short}
  </div>
);

export const Tick: React.FC<{
  state: 'yes' | 'no' | 'partial';
  label: string;
}> = ({state, label}) => {
  const color =
    state === 'yes'
      ? colors.good
      : state === 'no'
        ? colors.bad
        : colors.taproot;
  const symbol = state === 'yes' ? 'YES' : state === 'no' ? 'NO' : 'PARTIAL';
  return (
    <div style={{display: 'flex', alignItems: 'center', gap: 13}}>
      <span
        style={{
          minWidth: state === 'partial' ? 92 : 60,
          border: `1px solid ${color}77`,
          borderRadius: 999,
          padding: '6px 10px',
          color,
          background: `${color}12`,
          fontFamily: fonts.mono,
          fontWeight: 800,
          fontSize: 14,
          letterSpacing: 1.5,
          textAlign: 'center',
        }}
      >
        {symbol}
      </span>
      <span
        style={{
          color: colors.ink,
          fontFamily: fonts.body,
          fontWeight: 600,
          fontSize: 22,
        }}
      >
        {label}
      </span>
    </div>
  );
};

export const sceneOpacity = (
  frame: number,
  duration: number,
  fade = 20,
) =>
  interpolate(
    frame,
    [0, fade, duration - fade, duration],
    [0, 1, 1, 0],
    {...clamp, easing: Easing.inOut(Easing.cubic)},
  );
