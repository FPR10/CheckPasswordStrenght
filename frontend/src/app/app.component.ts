import {
  Component, OnInit, OnDestroy,
  signal, computed, inject
} from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule }  from '@angular/forms';
import {
  Subject, debounceTime, distinctUntilChanged,
  switchMap, catchError, of, takeUntil, tap
} from 'rxjs';

import { PasswordService }      from './password.service';
import { CheckCardComponent }   from './check-card.component';
import { AnimCounterDirective } from './anim-counter.directive';
import { AnalysisResult, LEVEL_CONFIG, LevelConfig } from './models';

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [CommonModule, FormsModule, CheckCardComponent, AnimCounterDirective],
  template: `
  <div class="shell">

    <!-- ── Header ── -->
    <header class="header">
      <span class="badge">NIST SP 800-63B</span>
      <h1 class="title">PASSWORD<br>SECURITY ANALYZER</h1>
      <p class="subtitle">ANALISI REAL-TIME · STANDARD FEDERALE USA · FASTAPI BACKEND</p>
    </header>

    <!-- ── Input ── -->
    <section class="input-section">
      <label class="field-label">// INSERISCI PASSWORD DA ANALIZZARE</label>

      <div class="input-wrapper"
           [style.border-color]="cfg() ? cfg()!.color + '55' : 'rgba(0,255,159,0.25)'">

        <input
          [type]="showPassword ? 'text' : 'password'"
          [(ngModel)]="passwordValue"
          (ngModelChange)="onPasswordChange($event)"
          placeholder="digita qui..."
          class="pw-input"
          autocomplete="off"
          spellcheck="false"
        />

        <button class="eye-btn" (click)="showPassword = !showPassword" type="button">
          {{ showPassword ? 'HIDE' : 'SHOW' }}
        </button>

        <!-- Barra di stato sotto l'input -->
        @if (result()) {
          <div class="status-bar">
            <div class="stat">
              <span class="stat-lbl">LUNGHEZZA</span>
              <span class="stat-val">{{ result()!.password_length }} chr</span>
            </div>
            <div class="stat">
              <span class="stat-lbl">ENTROPIA</span>
              <span class="stat-val">
                <span [animCounter]="result()!.entropy_bits" [decimals]="1"></span> bit
              </span>
            </div>
            <div class="stat">
              <span class="stat-lbl">CHARSET</span>
              <span class="stat-val">{{ result()!.charset_size }} sym</span>
            </div>
            <div class="stat">
              <span class="stat-lbl">SCORE</span>
              <span class="stat-val" [style.color]="cfg()?.color">
                <span [animCounter]="result()!.percentage" [decimals]="0"></span>%
              </span>
            </div>
          </div>
        }
      </div>
    </section>

    <!-- ── Loading ── -->
    @if (loading()) {
      <div class="loading-row">
        <span class="spinner"></span>
        ANALISI IN CORSO...
      </div>
    }

    <!-- ── Errore di connessione ── -->
    @if (error()) {
      <div class="error-box">⚠ {{ error() }}</div>
    }

    <!-- ── Risultati ── -->
    @if (result() && !loading()) {
      <div class="results">

        <!-- Meter sicurezza -->
        <div class="meter-card">
          <div class="meter-header">
            <span class="section-label">// LIVELLO SICUREZZA</span>
            <span class="level-badge"
                  [style.color]="cfg()!.color"
                  [style.border-color]="cfg()!.color"
                  [style.box-shadow]="'0 0 14px ' + cfg()!.glow">
              {{ result()!.level_label }}
            </span>
          </div>

          <div class="track">
            <div class="track-fill"
                 [style.width.%]="result()!.percentage"
                 [style.background]="'linear-gradient(90deg,' + cfg()!.color + '80,' + cfg()!.color + ')'"
                 [style.box-shadow]="'0 0 10px ' + cfg()!.glow">
            </div>
          </div>

          <div class="track-labels">
            <span>0</span><span>25</span><span>50</span><span>75</span><span>100</span>
          </div>
        </div>

        <!-- Tempo di crack stimato -->
        <div class="crack-box">
          <span class="crack-label">TEMPO STIMATO DI VIOLAZIONE &nbsp;(GPU · 10 miliardi/s)</span>
          <span class="crack-value"
                [style.color]="cfg()!.color"
                [style.text-shadow]="'0 0 12px ' + cfg()!.glow">
            {{ result()!.estimated_crack_time.toUpperCase() }}
          </span>
        </div>

        <!-- Griglia criteri NIST -->
        <p class="section-label" style="margin-bottom:12px">// CRITERI NIST SP 800-63B</p>
        <div class="checks-grid">
          @for (check of result()!.checks; track check.id) {
            <app-check-card [check]="check" />
          }
        </div>

        <!-- Raccomandazioni -->
        <div class="recs-box">
          <p class="section-label" style="margin-bottom:14px">// RACCOMANDAZIONI</p>
          @for (rec of result()!.recommendations; track rec) {
            <div class="rec-row">
              <span class="rec-arrow">→</span>
              <span>{{ rec }}</span>
            </div>
          }
        </div>

      </div>
    }

    <!-- ── Empty state ── -->
    @if (!passwordValue && !result() && !loading()) {
      <div class="empty-state">
        <div class="empty-icon">⬡</div>
        <p class="empty-text">
          DIGITA UNA PASSWORD PER INIZIARE L'ANALISI<span class="cursor">_</span>
        </p>
      </div>
    }

    <!-- ── Footer ── -->
    <footer class="footer">
      <span>NIST SP 800-63B — Digital Identity Guidelines</span>
      <span>BACKEND: FastAPI + Python</span>
    </footer>

  </div>
  `,
  styles: [`
    .shell {
      position: relative;
      z-index: 1;
      max-width: 800px;
      margin: 0 auto;
      padding: 52px 24px 80px;
      animation: fadeInUp 0.5s ease;
    }

    /* ── Header ─────────────────────────────────── */
    .header { margin-bottom: 52px; }

    .badge {
      display: inline-block;
      font-size: 10px;
      letter-spacing: 3px;
      padding: 4px 10px;
      border: 1px solid rgba(0,255,159,0.3);
      color: rgba(0,255,159,0.55);
      margin-bottom: 16px;
    }

    .title {
      font-size: clamp(26px, 5.5vw, 44px);
      font-weight: 800;
      letter-spacing: -0.02em;
      line-height: 1.1;
      color: var(--green);
      text-shadow: 0 0 30px rgba(0,255,159,0.25);
      margin-bottom: 10px;
    }

    .subtitle {
      font-size: 11px;
      color: rgba(0,255,159,0.38);
      letter-spacing: 2px;
    }

    /* ── Input ───────────────────────────────────── */
    .input-section { margin-bottom: 28px; }

    .field-label {
      display: block;
      font-size: 11px;
      letter-spacing: 3px;
      color: rgba(0,255,159,0.45);
      margin-bottom: 10px;
    }

    .input-wrapper {
      position: relative;
      border: 1px solid rgba(0,255,159,0.25);
      background: rgba(0,255,159,0.02);
      transition: border-color 0.3s, box-shadow 0.3s;
    }

    .input-wrapper:focus-within {
      border-color: rgba(0,255,159,0.55) !important;
      box-shadow: 0 0 22px rgba(0,255,159,0.1),
                  inset 0 0 20px rgba(0,255,159,0.02);
    }

    .pw-input {
      width: 100%;
      padding: 16px 64px 16px 20px;
      background: transparent;
      border: none;
      outline: none;
      font-family: var(--font);
      font-size: 18px;
      color: var(--text);
      caret-color: var(--green);
      letter-spacing: 0.05em;
    }

    .pw-input::placeholder { color: rgba(0,255,159,0.15); }

    .eye-btn {
      position: absolute;
      right: 16px;
      top: 50%;
      transform: translateY(-50%);
      background: none;
      border: none;
      color: rgba(0,255,159,0.4);
      cursor: pointer;
      font-family: var(--font);
      font-size: 11px;
      letter-spacing: 1px;
      padding: 4px;
      transition: color 0.2s;
    }
    .eye-btn:hover { color: var(--green); }

    /* Barra di stato */
    .status-bar {
      display: flex;
      flex-wrap: wrap;
      gap: 20px;
      padding: 12px 20px;
      border-top: 1px solid rgba(0,255,159,0.1);
      background: rgba(0,0,0,0.3);
    }
    .stat     { display: flex; flex-direction: column; gap: 2px; }
    .stat-lbl { font-size: 9px; letter-spacing: 2px; color: rgba(0,255,159,0.32); }
    .stat-val { font-size: 13px; color: var(--green); }

    /* ── Loading / Errore ────────────────────────── */
    .loading-row {
      display: flex;
      align-items: center;
      gap: 10px;
      font-size: 11px;
      letter-spacing: 2px;
      color: rgba(0,255,159,0.4);
      padding: 8px 0;
    }

    .spinner {
      display: inline-block;
      width: 12px; height: 12px;
      border: 2px solid rgba(0,255,159,0.1);
      border-top-color: var(--green);
      border-radius: 50%;
      animation: spin 0.7s linear infinite;
      flex-shrink: 0;
    }

    .error-box {
      padding: 14px 18px;
      border: 1px solid rgba(255,45,85,0.3);
      background: rgba(255,45,85,0.05);
      color: var(--red);
      font-size: 11px;
      line-height: 1.6;
    }

    /* ── Risultati ───────────────────────────────── */
    .section-label {
      font-size: 10px;
      letter-spacing: 3px;
      color: rgba(0,255,159,0.4);
    }

    .meter-card {
      padding: 22px 24px;
      border: 1px solid rgba(0,255,159,0.12);
      background: rgba(0,255,159,0.02);
      margin-bottom: 10px;
    }

    .meter-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 18px;
    }

    .level-badge {
      font-size: 13px;
      font-weight: 800;
      letter-spacing: 3px;
      padding: 4px 12px;
      border: 1px solid;
      transition: all 0.4s;
    }

    .track {
      height: 6px;
      background: rgba(0,255,159,0.08);
      overflow: hidden;
    }

    .track-fill {
      height: 100%;
      transition: width 0.65s cubic-bezier(0.4,0,0.2,1), background 0.4s;
    }

    .track-labels {
      display: flex;
      justify-content: space-between;
      margin-top: 8px;
    }
    .track-labels span {
      font-size: 9px;
      color: rgba(0,255,159,0.2);
      letter-spacing: 1px;
    }

    /* Tempo di crack */
    .crack-box {
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 12px;
      padding: 16px 24px;
      border: 1px solid rgba(0,255,159,0.1);
      background: rgba(0,0,0,0.3);
      margin-bottom: 24px;
    }
    .crack-label { font-size: 10px; letter-spacing: 2px; color: rgba(0,255,159,0.35); }
    .crack-value { font-size: 16px; font-weight: 700; letter-spacing: 1px; }

    /* Griglia check */
    .checks-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 10px;
      margin-bottom: 24px;
    }
    @media (max-width: 520px) {
      .checks-grid { grid-template-columns: 1fr; }
    }

    /* Raccomandazioni */
    .recs-box {
      padding: 20px 24px;
      border: 1px solid rgba(0,255,159,0.1);
      background: rgba(0,0,0,0.2);
    }
    .rec-row {
      display: flex;
      align-items: flex-start;
      gap: 10px;
      margin-bottom: 10px;
      font-size: 12px;
      color: rgba(200,255,230,0.65);
      line-height: 1.55;
    }
    .rec-row:last-child { margin-bottom: 0; }
    .rec-arrow { color: var(--green); flex-shrink: 0; margin-top: 2px; }

    /* ── Empty state ─────────────────────────────── */
    .empty-state {
      text-align: center;
      padding: 60px 0;
      color: rgba(0,255,159,0.15);
    }
    .empty-icon {
      font-size: 36px;
      margin-bottom: 18px;
      animation: scanPulse 2.5s ease-in-out infinite;
    }
    .empty-text { font-size: 11px; letter-spacing: 2px; }
    .cursor     { animation: blink 1s step-end infinite; }

    /* ── Footer ──────────────────────────────────── */
    .footer {
      margin-top: 52px;
      padding-top: 18px;
      border-top: 1px solid rgba(0,255,159,0.08);
      display: flex;
      justify-content: space-between;
      flex-wrap: wrap;
      gap: 8px;
      font-size: 10px;
      color: rgba(0,255,159,0.2);
      letter-spacing: 1px;
    }
  `]
})
export class AppComponent implements OnInit, OnDestroy {
  private svc     = inject(PasswordService);
  private destroy = new Subject<void>();
  private input$  = new Subject<string>();

  passwordValue = '';
  showPassword  = false;

  result  = signal<AnalysisResult | null>(null);
  loading = signal(false);
  error   = signal<string | null>(null);

  cfg = computed<LevelConfig | null>(() => {
    const r = this.result();
    return r ? (LEVEL_CONFIG[r.level] ?? null) : null;
  });

  ngOnInit(): void {
    this.input$.pipe(
      debounceTime(320),
      distinctUntilChanged(),
      tap(() => { this.loading.set(true); this.error.set(null); }),
      switchMap(pwd => {
        if (!pwd) {
          this.result.set(null);
          this.loading.set(false);
          return of(null);
        }
        return this.svc.analyze(pwd).pipe(
          catchError(() => {
            this.error.set(
              'Impossibile connettersi al backend. Avvia il server FastAPI su localhost:8000'
            );
            this.loading.set(false);
            return of(null);
          })
        );
      }),
      takeUntil(this.destroy)
    ).subscribe(res => {
      if (res) { this.result.set(res); this.error.set(null); }
      this.loading.set(false);
    });
  }

  onPasswordChange(value: string): void {
    this.input$.next(value);
  }

  ngOnDestroy(): void {
    this.destroy.next();
    this.destroy.complete();
  }
}