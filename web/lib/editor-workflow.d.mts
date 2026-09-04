export type EditorWorkflowStep = {
  id: string;
  title: string;
  description: string;
  paths: string[];
};
export function buildEditorWorkflow(resourceType: string, editablePaths: readonly string[]): EditorWorkflowStep[];
