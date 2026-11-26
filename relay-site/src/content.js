// Set to a real endpoint returning relay telemetry (JSON). Leave null until
// measurements exist. Never display figures without a timestamp and method.
export const TELEMETRY_URL = null;

// Six copy blocks, one per scroll segment. Bracketed text is a placeholder to
// replace with statements confirmed against the actual implementation.
export const COPY = [
  { title: 'Send first. Be seen later.' },
  { sub: '[Protocol promise: traffic is relayed through hops so no single relay sees both ends.]' },
  { sub: '[Mechanism: layered encryption, with one layer processed at each hop. Confirm against implementation.]' },
  { sub: '[Trust: relays are unlinkable and rotate. Confirm against implementation.]' },
  { sub: '[Trade-off: extra hops add latency. State the measured cost once measured.]' },
  { title: "Be someone else's first hop.", cta: { label: 'Run a relay', href: '#join' } },
];

// Eight hero dandelion petals that scatter across the viewport and crystallize
// into glassy feature frames (7 protocol features + 1 Start option)
export const PETAL_FRAMES = [
  {
    id: 'hops',
    no: '01',
    title: 'Multi-Hop Path',
    tag: 'Routing',
    summary: 'Packets cross independent relays instead of a direct link.',
    tx: 0.19, ty: 0.17, tilt: -2.4, detach: 0.30, arc: -0.09,
  },
  {
    id: 'layers',
    no: '02',
    title: 'Layered Crypto',
    tag: 'Security',
    summary: 'Encryption wraps the payload and peels cleanly at every hop.',
    tx: 0.45, ty: 0.15, tilt: 1.8, detach: 0.32, arc: -0.11,
  },
  {
    id: 'separation',
    no: '03',
    title: 'Origin Split',
    tag: 'Privacy',
    summary: 'No single relay observes both sender origin and destination.',
    tx: 0.77, ty: 0.16, tilt: -1.5, detach: 0.34, arc: -0.07,
  },
  {
    id: 'routing',
    no: '04',
    title: 'Path Selection',
    tag: 'Topology',
    summary: 'Independent relay paths rotate without central coordination.',
    tx: 0.50, ty: 0.43, tilt: 2.1, detach: 0.36, arc: -0.06,
  },
  {
    id: 'network',
    no: '05',
    title: 'Relay Network',
    tag: 'Operators',
    summary: 'Distributed infrastructure run by independent relay operators.',
    tx: 0.81, ty: 0.44, tilt: -1.8, detach: 0.38, arc: 0.05,
  },
  {
    id: 'performance',
    no: '06',
    title: 'Latency Budget',
    tag: 'Metrics',
    summary: 'Transparent per-hop latency cost and test methodology.',
    tx: 0.22, ty: 0.79, tilt: 1.4, detach: 0.40, arc: 0.09,
  },
  {
    id: 'transparency',
    no: '07',
    title: 'Open Spec',
    tag: 'Verify',
    summary: 'Architecture docs, threat model, limitations, and spec.',
    tx: 0.52, ty: 0.77, tilt: -2.0, detach: 0.42, arc: 0.08,
  },
  {
    id: 'join',
    no: 'START',
    title: 'Start Relay',
    tag: 'Begin',
    summary: 'Launch the tour, explore features, or run a relay.',
    isStart: true,
    ctaLabel: 'Start →',
    tx: 0.80, ty: 0.75, tilt: 1.2, detach: 0.44, arc: 0.07,
  },
];

// status: 'implemented' | 'experimental' | 'planned'
// visual: 'inspector' (interactive stages) | 'telemetry' | 'list'
export const FEATURES = [
  {
    id: 'hops', no: '01', title: 'Multi-Hop Communication', status: 'planned',
    summary: '[How messages travel through successive relays instead of a direct sender-to-recipient connection.]',
    purpose: '[Technical purpose of the relay path model.]',
    visual: 'inspector',
    items: [
      { label: 'Sender', detail: '[What the sender knows and what it sends.]' },
      { label: 'Relay 1', detail: '[What this relay can observe.]' },
      { label: 'Relay 2', detail: '[What this relay can observe.]' },
      { label: 'Recipient', detail: '[What the recipient receives and what it can see about prior hops.]' },
    ],
  },
  {
    id: 'layers', no: '02', title: 'Layered Encryption', status: 'planned',
    summary: '[How encryption layers are added and processed at successive hops, if the protocol does this.]',
    purpose: '[Cryptographic properties confirmed by the implementation only.]',
    visual: 'inspector',
    items: [
      { label: 'Outer layer', detail: '[Processed by the first relay. Confirm.]' },
      { label: 'Middle layer', detail: '[Processed by the next relay. Confirm.]' },
      { label: 'Inner payload', detail: '[What remains after all layers are removed. Confirm.]' },
    ],
  },
  {
    id: 'separation', no: '03', title: 'Sender and Recipient Separation', status: 'planned',
    summary: '[How the routing design limits what any single relay can observe.]',
    purpose: '[Actual privacy guarantees and their limits.]',
    visual: 'inspector',
    items: [
      { label: 'Sender', detail: '[Identity visible to: confirm.]' },
      { label: 'Relay', detail: '[Observable by a single relay: confirm.]' },
      { label: 'Recipient', detail: '[Identity visible to: confirm.]' },
    ],
  },
  {
    id: 'routing', no: '04', title: 'Relay Selection and Routing', status: 'planned',
    summary: '[How relay paths are selected and whether they change. State only what the implementation does.]',
    purpose: '[Selection criteria and path construction.]',
    visual: 'list',
    items: [
      '[Relay selection criteria: confirm from implementation]',
      '[Path construction: confirm from implementation]',
      '[Path change behavior: mark implemented, experimental or planned]',
    ],
  },
  {
    id: 'network', no: '05', title: 'Distributed Relay Network', status: 'planned',
    summary: '[How independent relay operators contribute infrastructure to the network.]',
    purpose: '[Role of operators and the network topology.]',
    visual: 'telemetry',
    items: ['[Operator model and onboarding: confirm]'],
  },
  {
    id: 'performance', no: '06', title: 'Network Performance', status: 'planned',
    summary: '[The honest latency trade-off of multi-hop routing.]',
    purpose: '[What is measured, how, and under which conditions.]',
    visual: 'telemetry',
    items: [
      'Methodology: [hardware, network conditions, hop count, sample size]',
      'Sample data and real measurements must be labeled separately.',
    ],
  },
  {
    id: 'transparency', no: '07', title: 'Protocol Transparency', status: 'planned',
    summary: '[Architecture, threat model, known limitations, and the specification.]',
    purpose: '[Where the verifiable design material lives.]',
    visual: 'list',
    items: [
      'Architecture document: [link]',
      'Threat model and security assumptions: [link]',
      'Known limitations: [link]',
      'Technical specification: [link]',
    ],
  },
  {
    id: 'join', no: '08', title: 'Developer and Relay Participation', status: 'planned',
    summary: '[How to run a relay and contribute to the codebase.]',
    purpose: '[Prerequisites and deployment requirements.]',
    visual: 'list',
    items: [
      'Prerequisites: [list]',
      'Relay operator guide: [link]',
      'Contribute: [GitHub repository link]',
    ],
  },
];
