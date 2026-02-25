import { Component, Input } from '@angular/core';
import { CommonModule } from '@angular/common';
import { CheckResult, SEVERITY_ICON } from './models';

/**
 * Card che visualizza il risultato di un singolo criterio NIST.
 * Cambia colore e icona in base a passed/severity.
 */
@Component({
  selector: 'app-check-card',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div class="card" [style.border-color]="borderColor" [style.background]="bgColor">

      <div class="top">
        <span class="icon" [style.color]="iconColor">{{ icon }}</span>
        <span class="label" [style.color]="check.passed ? 'rgba(200,255,230,0.85)' : iconColor">
          {{ check.label }}
        </span>
      </div>

      <p class="desc">{{ check.description }}</p>

      <div class="mini-track">
        <div class="mini-fill"
             [style.width.%]="barWidth"
             [style.background]="iconColor">
        </div>
      </div>

      <span class="ref">{{ check.nist_ref }}</span>
    </div>
  `,
  styles: [`
    .card {
      padding: 14px 16px;
      border: 1px solid;
      animation: fadeInUp 0.3s ease both;
      transition: border-color 0.3s;
    }
    .top {
      display: flex;
      align-items: flex-start;
      gap: 10px;
      margin-bottom: 6px;
    }
    .icon {
      font-size: 14px;
      flex-shrink: 0;
      margin-top: 1px;
    }
    .label {
      font-size: 11px;
      font-weight: 700;
      letter-spacing: 0.5px;
      line-height: 1.3;
    }
    .desc {
      font-size: 10px;
      color: rgba(200,255,230,0.45);
      line-height: 1.5;
      margin: 0;
    }
    .mini-track {
      height: 3px;
      background: rgba(0,255,159,0.08);
      margin-top: 10px;
      overflow: hidden;
    }
    .mini-fill {
      height: 100%;
      transition: width 0.5s 0.15s ease;
    }
    .ref {
      display: block;
      font-size: 9px;
      color: rgba(0,255,159,0.2);
      margin-top: 7px;
      letter-spacing: 0.5px;
    }
  `]
})
export class CheckCardComponent {
  @Input() check!: CheckResult;

  get iconColor(): string {
    if (this.check.passed) return '#00ff9f';
    return this.check.severity === 'critical' ? '#ff2d55' : '#ff6b35';
  }

  get borderColor(): string {
    if (this.check.passed) return 'rgba(0,255,159,0.18)';
    return this.check.severity === 'critical'
      ? 'rgba(255,45,85,0.4)'
      : 'rgba(255,107,53,0.3)';
  }

  get bgColor(): string {
    if (this.check.passed) return 'rgba(0,255,159,0.02)';
    return this.check.severity === 'critical'
      ? 'rgba(255,45,85,0.05)'
      : 'rgba(255,107,53,0.03)';
  }

  get icon(): string {
    return this.check.passed ? '✓' : SEVERITY_ICON[this.check.severity];
  }

  get barWidth(): number {
    return this.check.max_score > 0
      ? (this.check.score / this.check.max_score) * 100
      : 0;
  }
}