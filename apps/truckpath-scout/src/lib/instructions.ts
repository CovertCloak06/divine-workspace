import type { ApproachDirection, Drawing, Hazard, RiskResult, Site, TruckProfile } from '../types';
import { HAZARD_TYPE_MAP } from '../data/hazardTypes';

/**
 * Template-based driver instruction generator.
 * Deterministic for the MVP; see generateWithAi() below for the LLM hook.
 */

export interface PlanInput {
  site: Site;
  truck: TruckProfile;
  hazards: Hazard[];
  drawings: Drawing[];
  direction: ApproachDirection;
  avoidStreets: string[];
  stagingNotes: string;
  backingNotes: string;
  unloadingNotes: string;
  risk: RiskResult;
}

const DIRECTION_LABELS: Record<ApproachDirection, string> = {
  north: 'from the NORTH',
  northeast: 'from the NORTHEAST',
  east: 'from the EAST',
  southeast: 'from the SOUTHEAST',
  south: 'from the SOUTH',
  southwest: 'from the SOUTHWEST',
  west: 'from the WEST',
  northwest: 'from the NORTHWEST',
  unspecified: 'per site contact',
};

export function directionLabel(direction: ApproachDirection): string {
  return DIRECTION_LABELS[direction];
}

function hazardLine(h: Hazard): string {
  const def = HAZARD_TYPE_MAP[h.type];
  const note = h.notes ? ` — ${h.notes}` : '';
  return `${def.label}${note} [${h.severity.toUpperCase()}]`;
}

function buildDoList(input: PlanInput): string[] {
  const { site, truck, hazards, direction, stagingNotes, backingNotes, unloadingNotes } = input;
  const items: string[] = [];

  items.push(`Approach ${DIRECTION_LABELS[direction]}`);

  const entrance = hazards.find((h) => h.type === 'correct_entrance');
  if (entrance) {
    items.push(`Use the marked entrance${entrance.notes ? `: ${entrance.notes}` : ''}`);
  }
  if (stagingNotes) items.push(`Stage first: ${stagingNotes}`);
  if (site.backing_required) {
    items.push(backingNotes ? `Backing: ${backingNotes}` : 'Backing required — get a spotter before backing');
  }
  if (unloadingNotes) items.push(`Unloading: ${unloadingNotes}`);
  if (truck.height_ft >= 13) items.push(`Watch overhead clearance — vehicle is ${truck.height_ft} ft tall`);
  if (site.contact) items.push(`Call ${site.contact} before final approach`);
  if (items.length < 3) items.push('Reduce speed on final approach and watch for marked hazards');

  return items;
}

function buildAvoidList(input: PlanInput): string[] {
  const items: string[] = [...input.avoidStreets];
  const wrongEntrances = input.hazards.filter((h) => h.type === 'wrong_entrance');
  for (const w of wrongEntrances) {
    items.push(`Wrong entrance${w.notes ? `: ${w.notes}` : ' (marked on map)'}`);
  }
  const critical = input.hazards.filter(
    (h) => (h.severity === 'critical' || h.severity === 'high') && HAZARD_TYPE_MAP[h.type].category === 'hazard',
  );
  for (const c of critical) {
    items.push(`${HAZARD_TYPE_MAP[c.type].label}${c.notes ? `: ${c.notes}` : ''}`);
  }
  if (items.length === 0) items.push('No specific avoid list — follow marked approach');
  return items;
}

export function generateInstructions(input: PlanInput): string {
  const { site, truck, hazards, direction, stagingNotes, backingNotes, risk } = input;

  const hazardLines = hazards
    .filter((h) => HAZARD_TYPE_MAP[h.type].category === 'hazard')
    .sort((a, b) => severityRank(b.severity) - severityRank(a.severity))
    .map((h) => `- ${hazardLine(h)}`);

  const doList = buildDoList(input).map((i) => `- ${i}`);
  const avoidList = buildAvoidList(input).map((i) => `- ${i}`);

  const arrival: string[] = [];
  arrival.push(`- Stage at ${stagingNotes || 'the marked staging area (see map)'}`);
  if (site.contact) arrival.push(`- Call ${site.contact} before entering`);
  arrival.push(`- Use ${entranceText(input)}`);
  if (site.backing_required) {
    arrival.push(`- Back in ${backingNotes ? `— ${backingNotes}` : `from the approach direction with a spotter`}`);
  }

  return [
    'TRUCK DELIVERY APPROACH PLAN',
    '',
    'Truck:',
    `${truck.name} — ${truck.length_ft} ft L × ${truck.width_ft} ft W × ${truck.height_ft} ft H, ${truck.gross_weight_lbs.toLocaleString()} lbs GVW`,
    '',
    'Destination:',
    `${site.name}${site.address ? ` — ${site.address}` : ''}`,
    '',
    'Best approach:',
    `Approach ${DIRECTION_LABELS[direction]}`,
    '',
    'Do:',
    ...doList,
    '',
    'Avoid:',
    ...avoidList,
    '',
    'Arrival:',
    ...arrival,
    '',
    'Hazards:',
    ...(hazardLines.length ? hazardLines : ['- None marked']),
    '',
    'Risk:',
    `${risk.score}/10 — ${risk.label}`,
  ].join('\n');
}

/** Short SMS version, kept under 600 characters. */
export function generateSms(input: PlanInput): string {
  const { site, truck, direction, avoidStreets, stagingNotes, risk } = input;
  const parts: string[] = [];
  parts.push(`TRUCK PLAN: ${site.name}`);
  if (site.address) parts.push(site.address);
  parts.push(`${truck.name}. Approach ${DIRECTION_LABELS[direction]}.`);
  if (avoidStreets.length) parts.push(`AVOID: ${avoidStreets.slice(0, 3).join('; ')}.`);

  const topHazards = input.hazards
    .filter((h) => HAZARD_TYPE_MAP[h.type].category === 'hazard')
    .sort((a, b) => severityRank(b.severity) - severityRank(a.severity))
    .slice(0, 3)
    .map((h) => HAZARD_TYPE_MAP[h.type].label);
  if (topHazards.length) parts.push(`HAZARDS: ${topHazards.join(', ')}.`);

  if (stagingNotes) parts.push(`Stage: ${stagingNotes}.`);
  if (site.backing_required) parts.push('Backing required - use spotter.');
  if (site.contact) parts.push(`Call ${site.contact} before entering.`);
  parts.push(`Risk ${risk.score}/10 (${risk.label}).`);

  let sms = parts.join(' ');
  if (sms.length > 600) sms = `${sms.slice(0, 597)}...`;
  return sms;
}

function entranceText(input: PlanInput): string {
  const entrance = input.hazards.find((h) => h.type === 'correct_entrance');
  if (entrance?.notes) return `the marked entrance (${entrance.notes})`;
  if (entrance) return 'the entrance marked on the map';
  return 'the main entrance';
}

function severityRank(s: Hazard['severity']): number {
  return { low: 0, medium: 1, high: 2, critical: 3 }[s];
}

/**
 * FUTURE HOOK — AI-polished instructions.
 * Point VITE_AI_ENDPOINT at any OpenAI/Claude-compatible chat completions
 * endpoint and this replaces the template output with an LLM rewrite.
 * Falls back to the deterministic template on any failure.
 */
export async function generateWithAi(input: PlanInput): Promise<string> {
  const endpoint = import.meta.env.VITE_AI_ENDPOINT as string | undefined;
  const apiKey = import.meta.env.VITE_AI_API_KEY as string | undefined;
  const model = (import.meta.env.VITE_AI_MODEL as string | undefined) ?? 'claude-sonnet-5';
  const template = generateInstructions(input);
  if (!endpoint) return template;

  try {
    const res = await fetch(endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(apiKey ? { Authorization: `Bearer ${apiKey}` } : {}),
      },
      body: JSON.stringify({
        model,
        messages: [
          {
            role: 'system',
            content:
              'You rewrite truck delivery approach plans for drivers. Keep the exact section structure. Be concise, imperative, and field-practical. Never invent hazards or directions not in the input.',
          },
          { role: 'user', content: template },
        ],
        max_tokens: 1024,
      }),
    });
    if (!res.ok) return template;
    const data = await res.json();
    return data.choices?.[0]?.message?.content ?? template;
  } catch {
    return template;
  }
}
