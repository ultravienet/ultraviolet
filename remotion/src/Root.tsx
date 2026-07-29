import React from 'react';
import {Composition} from 'remotion';
import {
  RgbExplainer,
  ShieldedCsvExplainer,
  TaprootAssetsExplainer,
} from './ProtocolExplainer';
import {UltravioletComparison} from './UltravioletComparison';
import {UltravioletBenchmarks} from './UltravioletBenchmarks';

export const RemotionRoot: React.FC = () => {
  return (
    <>
      <Composition
        id="UltravioletComparison"
        component={UltravioletComparison}
        durationInFrames={1800}
        fps={30}
        width={1920}
        height={1080}
      />
      <Composition
        id="ShieldedCsvExplainer"
        component={ShieldedCsvExplainer}
        durationInFrames={1350}
        fps={30}
        width={1920}
        height={1080}
      />
      <Composition
        id="TaprootAssetsExplainer"
        component={TaprootAssetsExplainer}
        durationInFrames={1350}
        fps={30}
        width={1920}
        height={1080}
      />
      <Composition
        id="RgbExplainer"
        component={RgbExplainer}
        durationInFrames={1350}
        fps={30}
        width={1920}
        height={1080}
      />
      <Composition
        id="UltravioletBenchmarks"
        component={UltravioletBenchmarks}
        durationInFrames={1500}
        fps={30}
        width={1920}
        height={1080}
      />
    </>
  );
};
