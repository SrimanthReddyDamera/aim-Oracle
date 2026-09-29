import { createBrowserRouter } from 'react-router'
import App from './App'
import AppLayout from './app/layout/AppLayout'
import Login from './pages/auth/Login'
import Signup from './pages/auth/Signup'
import ForgotPassword from './pages/auth/ForgotPassword'
import ResetPassword from './pages/auth/ResetPassword'
import MFAVerification from './pages/auth/MFAVerification'
import OnboardingLayout from './pages/onboarding/OnboardingLayout'
import OrganizationSetup from './pages/onboarding/OrganizationSetup'
import ConnectIntegrations from './pages/onboarding/ConnectIntegrations'
import EnvironmentSetup from './pages/onboarding/EnvironmentSetup'
import OracleConfiguration from './pages/onboarding/OracleConfiguration'
import TeamInvitation from './pages/onboarding/TeamInvitation'
import OracleInitialization from './pages/onboarding/OracleInitialization'
import CommandCenter from './pages/dashboard/CommandCenter'
import IntelligenceCenter from './pages/intelligence/IntelligenceCenter'
import AIInvestigation from './pages/intelligence/AIInvestigation'
import OperationsOverview from './pages/operations/OperationsOverview'
import IncidentDetails from './pages/operations/IncidentDetails'
import DeploymentDetails from './pages/operations/DeploymentDetails'
import PipelineDetails from './pages/operations/PipelineDetails'
import Automation from './pages/operations/Automation'
import EngineeringOverview from './pages/engineering/EngineeringOverview'
import RepositoryDetails from './pages/engineering/RepositoryDetails'
import PullRequestDetails from './pages/engineering/PullRequestDetails'
import ChangeIntelligence from './pages/engineering/ChangeIntelligence'
import InfrastructureOverview from './pages/infrastructure/InfrastructureOverview'
import ResourceDetails from './pages/infrastructure/ResourceDetails'
import SystemTopology from './pages/infrastructure/SystemTopology'
import SecurityCenter from './pages/security/SecurityCenter'
import SecurityFinding from './pages/security/SecurityFinding'
import Integrations from './pages/integrations/Integrations'
import IntegrationDetails from './pages/integrations/IntegrationDetails'
import Settings from './pages/settings/Settings'

export const router = createBrowserRouter([
  { path: '/', Component: App },
  { path: '/login', Component: Login },
  { path: '/signup', Component: Signup },
  { path: '/forgot-password', Component: ForgotPassword },
  { path: '/reset-password', Component: ResetPassword },
  { path: '/mfa', Component: MFAVerification },
  {
    path: '/onboarding',
    Component: OnboardingLayout,
    children: [
      { index: true, Component: OrganizationSetup },
      { path: 'integrations', Component: ConnectIntegrations },
      { path: 'environment', Component: EnvironmentSetup },
      { path: 'configuration', Component: OracleConfiguration },
      { path: 'team', Component: TeamInvitation },
      { path: 'initialization', Component: OracleInitialization },
    ],
  },
  {
    path: '/app',
    Component: AppLayout,
    children: [
      { index: true, Component: CommandCenter },
      { path: 'intelligence', Component: IntelligenceCenter },
      { path: 'intelligence/investigation/:id', Component: AIInvestigation },
      { path: 'operations', Component: OperationsOverview },
      { path: 'operations/incidents/:id', Component: IncidentDetails },
      { path: 'operations/deployments/:id', Component: DeploymentDetails },
      { path: 'operations/pipelines/:id', Component: PipelineDetails },
      { path: 'operations/automation', Component: Automation },
      { path: 'engineering', Component: EngineeringOverview },
      { path: 'engineering/repos/:id', Component: RepositoryDetails },
      { path: 'engineering/prs/:id', Component: PullRequestDetails },
      { path: 'engineering/changes', Component: ChangeIntelligence },
      { path: 'infrastructure', Component: InfrastructureOverview },
      { path: 'infrastructure/resources/:id', Component: ResourceDetails },
      { path: 'infrastructure/topology', Component: SystemTopology },
      { path: 'security', Component: SecurityCenter },
      { path: 'security/findings/:id', Component: SecurityFinding },
      { path: 'integrations', Component: Integrations },
      { path: 'integrations/:id', Component: IntegrationDetails },
      { path: 'settings', Component: Settings },
    ],
  },
])
