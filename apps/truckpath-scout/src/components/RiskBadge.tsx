import { riskColor, riskLabel } from '../lib/risk';

export default function RiskBadge({ score, large = false }: { score: number; large?: boolean }) {
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full font-bold text-ink ${
        large ? 'px-4 py-2 text-lg' : 'px-3 py-1 text-sm'
      }`}
      style={{ backgroundColor: riskColor(score) }}
    >
      {score}/10 {riskLabel(score)}
    </span>
  );
}
