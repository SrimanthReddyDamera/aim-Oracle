export type Severity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export type InvestigationStage =
  | 'CREATED'
  | 'COLLECTING_EVIDENCE'
  | 'PLANNING'
  | 'INVESTIGATING'
  | 'HYPOTHESIS_REVIEW'
  | 'ROOT_CAUSE_IDENTIFIED'
  | 'RESOLUTION_PLANNED'
  | 'PROMPT_GENERATED'
  | 'AWAITING_AGENT'
  | 'PATCH_READY'
  | 'SANDBOX_QUEUED'
  | 'SANDBOX_RUNNING'
  | 'VERIFICATION_FAILED'
  | 'VERIFIED'
  | 'GATE_CLEARED'
  | 'BLOCKED'
  | 'INSUFFICIENT_EVIDENCE';

export type EvidenceCategory =
  | 'LOG'
  | 'CODE'
  | 'GIT'
  | 'DEPLOYMENT'
  | 'CONFIG'
  | 'METRIC'
  | 'DEPENDENCY'
  | 'EXTERNAL'
  | 'AST'
  | 'TEST'
  | 'REPOSITORY';

export interface EvidenceItem {
  id: string; // e.g. E-018
  source: string; // e.g. payment_service.py
  location?: string; // line 184
  line?: number;
  type: string; // Source Code, Production Log, Git Commit Diff, etc.
  category: EvidenceCategory;
  timestamp: string;
  relevance: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  confidence: number; // 0 - 100
  supportsHypotheses: string[]; // e.g. ['H-002']
  contradictsHypotheses: string[]; // e.g. ['H-001']
  provenance: string; // e.g. 'Repository → Commit 8f31a2'
  summary: string;
  content: string;
  metadata?: Record<string, string | number | boolean>;
}

export interface Hypothesis {
  id: string; // e.g. H-001, H-002
  title: string;
  description: string;
  status: 'STRONGLY_SUPPORTED' | 'POSSIBLE' | 'REJECTED' | 'CONFIRMED' | 'INSUFFICIENT_EVIDENCE';
  supportingEvidenceIds: string[];
  contradictingEvidenceIds: string[];
  supportingCount?: number;
  contradictingCount?: number;
  rationale: string;
  evaluatorNote?: string;
}

export interface RootCauseRecord {
  title: string;
  confidence: number; // e.g. 94%
  status: 'STRONGLY_SUPPORTED' | 'PROBABLE' | 'INSUFFICIENT_DATA' | 'INSUFFICIENT_EVIDENCE' | 'AMBIGUOUS_ROOT_CAUSE' | 'CONTRADICTED';
  explanationChain: string[];
  supportingEvidenceIds: string[];
  contradictingEvidenceIds: string[];
  contradictionNotes: string;
  identifiedAt: string;
  missingEvidence?: string[];
  recommendedNextActions?: string[];
  recommendationIfInsufficient?: string[];
}

export interface ResolutionPlan {
  recommendation: string;
  affectedFiles: string[];
  steps: string[];
  risk: 'LOW' | 'MEDIUM' | 'HIGH';
  sideEffects: string;
  suggestedTests: string[];
  backwardCompatibilityNotes?: string;
}

export type AgentTargetFormat = 'Claude Code' | 'Claude CLI' | 'Codex' | 'Generic Coding Agent';

export interface AgentTask {
  id: string;
  investigationId: string;
  targetFormat: AgentTargetFormat;
  title: string;
  prompt: string;
  constraints: string[];
  requiredTests: string[];
  verificationRequirements: string[];
  createdAt: string;
}

export interface SandboxStage {
  step: number;
  name: string;
  label: string;
  sub: string;
  status: 'WAITING' | 'RUNNING' | 'PASSED' | 'FAILED';
}

export interface PillarProof {
  status: 'PASSED' | 'FAILED' | 'PENDING';
  title: string;
  summary: string;
  details: string;
}

export interface DeploymentGate {
  status: 'LOCKED' | 'CLEARED' | 'BLOCKED';
  verdict: 'FIX VERIFIED' | 'DEPLOYMENT BLOCKED' | 'AWAITING VERIFICATION';
  reason: string;
  checks: {
    negativeProof: boolean;
    zeroRegressions: boolean;
    scopeContainment: boolean;
    cryptographicAttestation: boolean;
  };
  clearedAt?: string;
}

export interface VerificationResult {
  status: 'VERIFIED' | 'FAILED' | 'PENDING';
  originalErrorEliminated: boolean;
  regressionTestsPassed: boolean;
  existingTestsBroken: number;
  totalRegressionTests: number;
  passedRegressionTests: number;
  staticAnalysisClean: boolean;
  scopeContained: boolean;
  targetFilesCount: number;
  modifiedFilesCount: number;
  unexpectedModificationsCount: number;
  boundaryViolationsCount: number;
  diffSummary: {
    filesChanged: number;
    insertions: number;
    deletions: number;
  };
  verdictMessage: string;
  failureReason?: string;
  recommendedAction?: string;
  verifiedAt?: string;
  testCommand?: string;
  testScript?: string;
  gitPatch?: string;
  terminalOutput?: string;
  isRealSandbox?: boolean;
  attestation?: {
    token: string;
    digest: string;
    containerId: string;
    signer: string;
    gateStatus: string;
    timestamp: string;
    isMockDemo?: boolean;
    signatureHex?: string;
    publicKeyHex?: string;
  };
}

export interface TimelineEvent {
  id: string;
  timestamp: string;
  action: string;
  stage: InvestigationStage;
  status: 'COMPLETED' | 'IN_PROGRESS' | 'FAILED';
  evidenceRef?: string;
  details: string;
}

export interface TopologyNode {
  id: string;
  label: string;
  type: 'GATEWAY' | 'SERVICE' | 'DATABASE' | 'CACHE' | 'THIRD_PARTY';
  status: 'HEALTHY' | 'DEGRADED' | 'FAILED';
}

export interface TopologyEdge {
  source: string;
  target: string;
  label?: string;
  protocol?: string;
}

export interface IncidentInvestigation {
  id: string; // e.g. INC-1042 or ORC-INC-2026-0402
  title: string;
  severity: Severity;
  service: string;
  environment: string;
  createdAt: string;
  stage: InvestigationStage;
  confidence: number;
  blastRadius?: string;
  jiraKey?: string;
  pullRequest?: string;
  upstreamCaller?: string;
  downstreamDependency?: string;
  context: {
    deployment: string;
    repository: string;
    commit: string;
    cloudProvider: string;
    timeRange: string;
    stackTraceRaw: string;
    additionalNotes?: string;
  };
  timeline: TimelineEvent[];
  evidence: EvidenceItem[];
  hypotheses: Hypothesis[];
  rootCause?: RootCauseRecord;
  resolution?: ResolutionPlan;
  verification?: VerificationResult;
  deploymentGate?: DeploymentGate;
  topology?: {
    nodes: TopologyNode[];
    edges: TopologyEdge[];
  };
}

export interface SystemMetrics {
  activeInvestigations: number;
  investigationsCompleted: number;
  verifiedResolutions: number;
  evidenceItemsProcessed: number;
  sandboxReplays?: number;
  deploymentGatesCleared?: number;
  deploymentGatesBlocked?: number;
  deploymentGatesAwaiting?: number;
  isMockData?: boolean;
}

export interface SecurityAuditEvent {
  id: string;
  timestamp: string;
  actor: string;
  action: string;
  target: string;
  status: 'VERIFIED' | 'SATISFIED' | 'ALERT';
  hash: string;
  details?: string;
}
