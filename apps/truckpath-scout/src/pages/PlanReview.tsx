import { useMemo, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import PlanSheet from '../components/PlanSheet';
import TopBar from '../components/TopBar';
import { encodePlanToUrl } from '../lib/share';
import { getPlan, getSite, getTruck, listDrawings, listHazards } from '../lib/storage';
import type { PlanBundle } from '../types';

export default function PlanReview() {
  const { siteId = '', planId = '' } = useParams();
  const navigate = useNavigate();
  const [copied, setCopied] = useState<'link' | 'sms' | null>(null);

  const bundle: PlanBundle | null = useMemo(() => {
    const site = getSite(siteId);
    const plan = getPlan(planId);
    if (!site || !plan) return null;
    const truck = getTruck(plan.truck_profile_id);
    if (!truck) return null;
    return { site, truck, plan, hazards: listHazards(siteId), drawings: listDrawings(siteId) };
  }, [siteId, planId]);

  if (!bundle) {
    return (
      <div className="p-6 text-center">
        <p className="mb-4">Plan not found.</p>
        <button className="btn-primary" onClick={() => navigate('/')}>Back to Dashboard</button>
      </div>
    );
  }

  async function copy(text: string, which: 'link' | 'sms') {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(which);
      setTimeout(() => setCopied(null), 2000);
    } catch {
      prompt('Copy this:', text);
    }
  }

  async function share() {
    const url = encodePlanToUrl(bundle!);
    if (navigator.share) {
      try {
        await navigator.share({ title: `Truck plan: ${bundle!.site.name}`, url });
        return;
      } catch {
        /* user cancelled — fall through to copy */
      }
    }
    copy(url, 'link');
  }

  return (
    <div className="min-h-full flex flex-col">
      <TopBar title="Plan Review" back={`/sites/${siteId}`} />
      <main className="flex-1 p-4 max-w-2xl w-full mx-auto space-y-4">
        <PlanSheet bundle={bundle} />

        <div className="no-print grid grid-cols-2 gap-2">
          <button className="btn-secondary" onClick={() => copy(bundle.plan.sms_text, 'sms')}>
            {copied === 'sms' ? '✓ Copied' : '💬 Copy SMS'}
          </button>
          <a className="btn-secondary" href={`sms:?body=${encodeURIComponent(bundle.plan.sms_text)}`}>
            📲 Text Driver
          </a>
          <button className="btn-secondary" onClick={share}>
            {copied === 'link' ? '✓ Link Copied' : '🔗 Share Link'}
          </button>
          <button className="btn-primary" onClick={() => window.print()}>
            🖨️ Export PDF
          </button>
        </div>
        <p className="no-print text-xs text-gray-500 text-center pb-4">
          Export PDF uses your browser&apos;s print dialog — choose “Save as PDF”. Share links embed the full plan;
          the recipient needs no account.
        </p>
      </main>
    </div>
  );
}
