/**
 * Synthesizes a futuristic security alert tone using the Web Audio API.
 * Completely offline, zero asset downloads required.
 */
class SoundEffects {
  private ctx: AudioContext | null = null;
  private enabled: boolean = true;

  constructor() {
    // AudioContext will be initialized on first user gesture
  }

  private getContext(): AudioContext | null {
    if (!this.ctx && typeof window !== 'undefined') {
      const AudioCtx = window.AudioContext || (window as any).webkitAudioContext;
      if (AudioCtx) {
        this.ctx = new AudioCtx();
      }
    }
    if (this.ctx && this.ctx.state === 'suspended') {
      this.ctx.resume();
    }
    return this.ctx;
  }

  public setEnabled(val: boolean) {
    this.enabled = val;
  }

  public isEnabled(): boolean {
    return this.enabled;
  }

  public toggle(): boolean {
    this.enabled = !this.enabled;
    return this.enabled;
  }

  /**
   * Two-tone cybersecurity warning alert: 880Hz -> 440Hz pulse
   */
  public playAlertSound() {
    if (!this.enabled) return;

    try {
      const ctx = this.getContext();
      if (!ctx) return;

      const now = ctx.currentTime;
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();

      osc.type = 'sawtooth';
      osc.frequency.setValueAtTime(880, now);
      osc.frequency.exponentialRampToValueAtTime(440, now + 0.15);

      gain.gain.setValueAtTime(0.08, now);
      gain.gain.exponentialRampToValueAtTime(0.001, now + 0.25);

      osc.connect(gain);
      gain.connect(ctx.destination);

      osc.start(now);
      osc.stop(now + 0.25);
    } catch {
      // Audio playback blocked or unsupported
    }
  }

  /**
   * Distinctive urgent alarm tone for Fake Online Shopping / Insecure Site warning
   * 988Hz -> 659Hz double pulse
   */
  public playFakeSiteAlertSound() {
    if (!this.enabled) return;

    try {
      const ctx = this.getContext();
      if (!ctx) return;

      const now = ctx.currentTime;
      const pulses = [
        { f: 988, start: 0, end: 0.12 },
        { f: 659, start: 0.12, end: 0.24 },
        { f: 988, start: 0.26, end: 0.38 },
        { f: 659, start: 0.38, end: 0.52 },
      ];

      pulses.forEach(({ f, start, end }) => {
        const osc = ctx.createOscillator();
        const gain = ctx.createGain();
        osc.type = 'sawtooth';
        osc.frequency.setValueAtTime(f, now + start);
        gain.gain.setValueAtTime(0.12, now + start);
        gain.gain.exponentialRampToValueAtTime(0.001, now + end);
        osc.connect(gain);
        gain.connect(ctx.destination);
        osc.start(now + start);
        osc.stop(now + end);
      });
    } catch {
      // Audio playback blocked
    }
  }
}

export const soundManager = new SoundEffects();
