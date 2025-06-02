import { promises as fs } from 'fs';
import path from 'path';

/**
 * Code snippet interface for consultation
 */
export interface CodeSnippet {
  filepath: string;
  snippet: string;
  line_range?: string;
  language?: string;
  context?: string;
}

/**
 * Consultation request interface
 */
export interface ConsultationRequest {
  issue_description: string;
  code_snippets: CodeSnippet[];
  project_context?: string;
  error_logs?: string;
  attempted_solutions?: string[];
  environment_info?: string;
  urgency_level?: "low" | "medium" | "high" | "critical";
}

/**
 * Detects programming language based on file extension
 */
export function detectLanguage(filepath: string): string {
  const ext = path.extname(filepath).toLowerCase();
  const languageMap: Record<string, string> = {
    '.js': 'javascript',
    '.jsx': 'jsx',
    '.ts': 'typescript',
    '.tsx': 'tsx',
    '.py': 'python',
    '.java': 'java',
    '.c': 'c',
    '.cpp': 'cpp',
    '.cc': 'cpp',
    '.cxx': 'cpp',
    '.h': 'c',
    '.hpp': 'cpp',
    '.cs': 'csharp',
    '.go': 'go',
    '.rs': 'rust',
    '.php': 'php',
    '.rb': 'ruby',
    '.swift': 'swift',
    '.kt': 'kotlin',
    '.scala': 'scala',
    '.sh': 'bash',
    '.bash': 'bash',
    '.zsh': 'zsh',
    '.fish': 'fish',
    '.ps1': 'powershell',
    '.html': 'html',
    '.htm': 'html',
    '.css': 'css',
    '.scss': 'scss',
    '.sass': 'sass',
    '.less': 'less',
    '.json': 'json',
    '.xml': 'xml',
    '.yaml': 'yaml',
    '.yml': 'yaml',
    '.toml': 'toml',
    '.ini': 'ini',
    '.conf': 'config',
    '.config': 'config',
    '.md': 'markdown',
    '.txt': 'text',
    '.log': 'log',
    '.sql': 'sql',
    '.dockerfile': 'dockerfile',
    '.dockerignore': 'dockerignore',
    '.gitignore': 'gitignore',
  };

  if (filepath.toLowerCase().includes('dockerfile')) return 'dockerfile';
  if (filepath.toLowerCase().includes('makefile')) return 'makefile';
  if (filepath.toLowerCase().includes('readme')) return 'markdown';

  return languageMap[ext] || 'text';
}

/**
 * Reads a single file and returns CodeSnippet object
 */
export async function readFileContent(
  filepath: string,
  projectRoot: string = process.cwd()
): Promise<CodeSnippet> {
  try {
    const fullPath = path.resolve(projectRoot, filepath);
    const content = await fs.readFile(fullPath, 'utf-8');
    const relativePath = path.relative(projectRoot, fullPath);
    
    return {
      filepath: relativePath,
      snippet: content,
      language: detectLanguage(filepath)
    };
  } catch (error: any) {
    throw new Error(`Failed to read file ${filepath}: ${error.message}`);
  }
}

/**
 * Reads multiple files and returns an array of CodeSnippet objects
 */
export async function readMultipleFiles(
  filepaths: string[],
  projectRoot: string = process.cwd()
): Promise<CodeSnippet[]> {
  const results: CodeSnippet[] = [];
  const errors: string[] = [];

  for (const filepath of filepaths) {
    try {
      const fileContent = await readFileContent(filepath, projectRoot);
      results.push(fileContent);
    } catch (error: any) {
      errors.push(`${filepath}: ${error.message}`);
    }
  }

  if (errors.length > 0) {
    console.warn('Some files could not be read:', errors);
  }

  return results;
}

/**
 * Automatically discovers relevant files in a project directory
 */
export async function discoverProjectFiles(
  projectRoot: string = process.cwd(),
  options: {
    includePatterns?: string[];
    excludePatterns?: string[];
    maxFiles?: number;
    maxFileSize?: number; // in bytes
  } = {}
): Promise<string[]> {
  const {
    includePatterns = [
      '**/*.js', '**/*.jsx', '**/*.ts', '**/*.tsx',
      '**/*.py', '**/*.java', '**/*.go', '**/*.rs',
      '**/*.cpp', '**/*.c', '**/*.h', '**/*.hpp',
      '**/package.json', '**/requirements.txt', '**/go.mod',
      '**/Cargo.toml', '**/pom.xml', '**/build.gradle',
      '**/Dockerfile', '**/docker-compose.yml',
      '**/*.md', '**/*.yaml', '**/*.yml', '**/*.json'
    ],
    excludePatterns = [
      '**/node_modules/**', '**/dist/**', '**/build/**',
      '**/.git/**', '**/.next/**', '**/.nuxt/**',
      '**/vendor/**', '**/target/**', '**/bin/**',
      '**/__pycache__/**', '**/*.pyc', '**/.venv/**',
      '**/coverage/**', '**/.coverage/**', '**/test-results/**'
    ],
    maxFiles = 50,
    maxFileSize = 1024 * 1024 // 1MB
  } = options;

  const files: string[] = [];
  
  try {
    const globbyModule = await import('globby');
    const globby = globbyModule.default;
    
    const foundFiles = await globby(includePatterns, {
      cwd: projectRoot,
      ignore: excludePatterns,
      dot: false,
      followSymbolicLinks: false
    });

    // Filter by file size and limit count
    for (const file of foundFiles) {
      if (files.length >= maxFiles) break;
      
      try {
        const fullPath = path.resolve(projectRoot, file);
        const stats = await fs.stat(fullPath);
        
        if (stats.size <= maxFileSize) {
          files.push(file);
        }
      } catch (error) {
        // Skip files that can't be accessed
        continue;
      }
    }
  } catch (error) {
    // Fallback to basic file discovery if globby is not available
    console.warn('Globby not available, using basic file discovery');
    return await basicFileDiscovery(projectRoot, maxFiles);
  }

  return files;
}

/**
 * Basic file discovery fallback when globby is not available
 */
async function basicFileDiscovery(
  dir: string,
  maxFiles: number,
  currentFiles: string[] = []
): Promise<string[]> {
  if (currentFiles.length >= maxFiles) return currentFiles;

  try {
    const entries = await fs.readdir(dir, { withFileTypes: true });
    
    for (const entry of entries) {
      if (currentFiles.length >= maxFiles) break;
      
      const fullPath = path.join(dir, entry.name);
      
      if (entry.isDirectory()) {
        // Skip common directories to exclude
        if (['node_modules', '.git', 'dist', 'build', '.next'].includes(entry.name)) {
          continue;
        }
        await basicFileDiscovery(fullPath, maxFiles, currentFiles);
      } else if (entry.isFile()) {
        const ext = path.extname(entry.name).toLowerCase();
        const relevantExtensions = [
          '.js', '.jsx', '.ts', '.tsx', '.py', '.java', '.go', '.rs',
          '.cpp', '.c', '.h', '.hpp', '.json', '.md', '.yml', '.yaml'
        ];
        
        if (relevantExtensions.includes(ext) || 
            ['package.json', 'requirements.txt', 'Dockerfile'].includes(entry.name)) {
          currentFiles.push(path.relative(process.cwd(), fullPath));
        }
      }
    }
  } catch (error) {
    // Skip directories that can't be accessed
  }

  return currentFiles;
}

/**
 * Collects system and environment information
 */
export function collectEnvironmentInfo(): string {
  const info: string[] = [];
  
  // Node.js version
  if (typeof process !== 'undefined') {
    info.push(`Node.js: ${process.version}`);
    info.push(`Platform: ${process.platform} ${process.arch}`);
    info.push(`OS: ${process.platform}`);
  }

  // Check for common package managers and their versions
  try {
    const packageJson = require(path.join(process.cwd(), 'package.json'));
    if (packageJson) {
      info.push(`Project: ${packageJson.name || 'Unknown'} v${packageJson.version || 'Unknown'}`);
      if (packageJson.engines) {
        info.push(`Engines: ${JSON.stringify(packageJson.engines)}`);
      }
    }
  } catch (error) {
    // package.json not found or not readable
  }

  return info.join('\n');
}

/**
 * Prepares a complete consultation request with automatic file discovery
 */
export async function prepareConsultationRequest(
  issueDescription: string,
  options: {
    specificFiles?: string[];
    projectRoot?: string;
    projectContext?: string;
    errorLogs?: string;
    attemptedSolutions?: string[];
    urgencyLevel?: "low" | "medium" | "high" | "critical";
    autoDiscoverFiles?: boolean;
    maxFiles?: number;
  } = {}
): Promise<ConsultationRequest> {
  const {
    specificFiles = [],
    projectRoot = process.cwd(),
    autoDiscoverFiles = true,
    maxFiles = 20
  } = options;

  let filesToRead = [...specificFiles];

  // Auto-discover files if enabled and no specific files provided
  if (autoDiscoverFiles && specificFiles.length === 0) {
    const discoveredFiles = await discoverProjectFiles(projectRoot, { maxFiles });
    filesToRead = discoveredFiles;
  }

  // Read file contents
  const filesContent = await readMultipleFiles(filesToRead, projectRoot);

  // Collect environment info
  const environmentInfo = collectEnvironmentInfo();

  return {
    issue_description: issueDescription,
    code_snippets: filesContent,
    project_context: options.projectContext || "Auto-generated consultation request",
    error_logs: options.errorLogs,
    attempted_solutions: options.attemptedSolutions || [],
    environment_info: environmentInfo,
    urgency_level: options.urgencyLevel || "medium"
  };
}

/**
 * Helper function to format consultation response for display
 */
export function formatConsultationResponse(response: any): string {
  if (typeof response === 'string') {
    return response;
  }

  if (!response || typeof response !== 'object') {
    return `## Expert Consultation Response\n\n\`\`\`json\n${JSON.stringify(response, null, 2)}\n\`\`\``;
  }

  const sections: string[] = [];

  // Add consultation metadata
  if (response.consultation_id || response.confidence_score) {
    let metadata = '';
    if (response.consultation_id) metadata += `**Consultation ID:** ${response.consultation_id}\n`;
    if (response.confidence_score) metadata += `**Confidence Score:** ${response.confidence_score}/100\n`;
    if (metadata) sections.push(`## 📊 Consultation Overview\n${metadata}`);
  }

  // Root Cause Analysis
  if (response.issue_analysis?.root_cause_analysis) {
    const rca = response.issue_analysis.root_cause_analysis;
    let analysis = '';
    
    if (rca.primary_cause) {
      analysis += `**Primary Cause:**\n${rca.primary_cause}\n\n`;
    }
    
    if (rca.contributing_factors && Array.isArray(rca.contributing_factors)) {
      analysis += `**Contributing Factors:**\n${rca.contributing_factors.map((factor: string, i: number) => `${i + 1}. ${factor}`).join('\n')}\n\n`;
    }
    
    if (rca.impact_assessment) {
      analysis += `**Impact Assessment:** ${rca.impact_assessment}\n`;
    }
    
    if (rca.complexity_rating) {
      analysis += `**Complexity Rating:** ${rca.complexity_rating}\n`;
    }
    
    if (analysis) sections.push(`## 🔍 Root Cause Analysis\n${analysis}`);
  }

  // Code Quality Assessment
  if (response.issue_analysis?.code_quality_assessment) {
    const cqa = response.issue_analysis.code_quality_assessment;
    let quality = '';
    
    if (cqa.code_smells && Array.isArray(cqa.code_smells)) {
      quality += `**Code Smells:**\n${cqa.code_smells.map((smell: string, i: number) => `${i + 1}. ${smell}`).join('\n')}\n\n`;
    }
    
    if (cqa.maintainability_score) {
      quality += `**Maintainability Score:** ${cqa.maintainability_score}/100\n`;
    }
    
    if (cqa.readability_score) {
      quality += `**Readability Score:** ${cqa.readability_score}/100\n`;
    }
    
    if (quality) sections.push(`## 📈 Code Quality Assessment\n${quality}`);
  }

  // Immediate Fixes
  if (response.solution_recommendations?.immediate_fixes && Array.isArray(response.solution_recommendations.immediate_fixes)) {
    const fixes = response.solution_recommendations.immediate_fixes;
    let fixesText = '';
    
    fixes.forEach((fix: any, index: number) => {
      fixesText += `### ${index + 1}. ${fix.fix_description || 'Fix'}\n\n`;
      
      if (fix.implementation_steps && Array.isArray(fix.implementation_steps)) {
        fixesText += `**Implementation Steps:**\n${fix.implementation_steps.map((step: string, i: number) => `${i + 1}. ${step}`).join('\n')}\n\n`;
      }
      
      if (fix.code_changes && Array.isArray(fix.code_changes)) {
        fixesText += `**Code Changes:**\n`;
        fix.code_changes.forEach((change: any) => {
          if (change.file_path) fixesText += `- **File:** \`${change.file_path}\`\n`;
          if (change.changes) fixesText += `- **Change:** \`${change.changes}\`\n`;
          if (change.rationale) fixesText += `- **Rationale:** ${change.rationale}\n`;
        });
        fixesText += '\n';
      }
      
      if (fix.risk_level) {
        fixesText += `**Risk Level:** ${fix.risk_level}\n\n`;
      }
      
      if (fix.testing_requirements && Array.isArray(fix.testing_requirements)) {
        fixesText += `**Testing Requirements:**\n${fix.testing_requirements.map((req: string, i: number) => `${i + 1}. ${req}`).join('\n')}\n\n`;
      }
    });
    
    if (fixesText) sections.push(`## ⚡ Immediate Fixes\n${fixesText}`);
  }

  // Long-term Improvements
  if (response.solution_recommendations?.long_term_improvements && Array.isArray(response.solution_recommendations.long_term_improvements)) {
    const improvements = response.solution_recommendations.long_term_improvements;
    let improvementsText = '';
    
    improvements.forEach((improvement: any, index: number) => {
      improvementsText += `### ${index + 1}. ${improvement.improvement_description || 'Improvement'}\n\n`;
      
      if (improvement.benefits && Array.isArray(improvement.benefits)) {
        improvementsText += `**Benefits:**\n${improvement.benefits.map((benefit: string, i: number) => `${i + 1}. ${benefit}`).join('\n')}\n\n`;
      }
      
      if (improvement.implementation_timeline) {
        improvementsText += `**Timeline:** ${improvement.implementation_timeline}\n\n`;
      }
      
      if (improvement.resource_requirements && Array.isArray(improvement.resource_requirements)) {
        improvementsText += `**Required Resources:** ${improvement.resource_requirements.join(', ')}\n\n`;
      }
    });
    
    if (improvementsText) sections.push(`## 🚀 Long-term Improvements\n${improvementsText}`);
  }

  // Alternative Approaches
  if (response.solution_recommendations?.alternative_approaches && Array.isArray(response.solution_recommendations.alternative_approaches)) {
    const approaches = response.solution_recommendations.alternative_approaches;
    let approachesText = '';
    
    approaches.forEach((approach: any, index: number) => {
      approachesText += `### ${index + 1}. ${approach.approach_name || 'Alternative Approach'}\n\n`;
      
      if (approach.pros && Array.isArray(approach.pros)) {
        approachesText += `**Pros:**\n${approach.pros.map((pro: string, i: number) => `${i + 1}. ${pro}`).join('\n')}\n\n`;
      }
      
      if (approach.cons && Array.isArray(approach.cons)) {
        approachesText += `**Cons:**\n${approach.cons.map((con: string, i: number) => `${i + 1}. ${con}`).join('\n')}\n\n`;
      }
      
      if (approach.implementation_effort) {
        approachesText += `**Implementation Effort:** ${approach.implementation_effort}\n\n`;
      }
    });
    
    if (approachesText) sections.push(`## 🔄 Alternative Approaches\n${approachesText}`);
  }

  // Architectural Guidance
  if (response.architectural_guidance) {
    let architecturalText = '';
    
    if (response.architectural_guidance.design_patterns && Array.isArray(response.architectural_guidance.design_patterns)) {
      architecturalText += `**Design Patterns:**\n`;
      response.architectural_guidance.design_patterns.forEach((pattern: any, index: number) => {
        architecturalText += `${index + 1}. **${pattern.pattern_name}**\n`;
        if (pattern.applicability) architecturalText += `   ${pattern.applicability}\n`;
        if (pattern.benefits && Array.isArray(pattern.benefits)) {
          architecturalText += `   Benefits: ${pattern.benefits.join(', ')}\n`;
        }
        architecturalText += '\n';
      });
    }
    
    if (response.architectural_guidance.refactoring_suggestions && Array.isArray(response.architectural_guidance.refactoring_suggestions)) {
      architecturalText += `**Refactoring Suggestions:**\n`;
      response.architectural_guidance.refactoring_suggestions.forEach((suggestion: any, index: number) => {
        architecturalText += `${index + 1}. **${suggestion.target_area}**\n`;
        if (suggestion.refactoring_technique) architecturalText += `   Technique: ${suggestion.refactoring_technique}\n`;
        if (suggestion.expected_outcome) architecturalText += `   Expected Outcome: ${suggestion.expected_outcome}\n`;
        architecturalText += '\n';
      });
    }
    
    if (architecturalText) sections.push(`## 🏗️ Architectural Guidance\n${architecturalText}`);
  }

  // Best Practices
  if (response.best_practices) {
    let practicesText = '';
    
    if (response.best_practices.coding_standards?.language_specific && Array.isArray(response.best_practices.coding_standards.language_specific)) {
      practicesText += `**Language-Specific Standards:**\n${response.best_practices.coding_standards.language_specific.map((standard: string, i: number) => `${i + 1}. ${standard}`).join('\n')}\n\n`;
    }
    
    if (response.best_practices.security_practices?.vulnerability_prevention && Array.isArray(response.best_practices.security_practices.vulnerability_prevention)) {
      practicesText += `**Security Practices:**\n${response.best_practices.security_practices.vulnerability_prevention.map((practice: string, i: number) => `${i + 1}. ${practice}`).join('\n')}\n\n`;
    }
    
    if (response.best_practices.testing_strategies?.unit_testing && Array.isArray(response.best_practices.testing_strategies.unit_testing)) {
      practicesText += `**Testing Strategies:**\n${response.best_practices.testing_strategies.unit_testing.slice(0, 3).map((strategy: string, i: number) => `${i + 1}. ${strategy}`).join('\n')}\n\n`;
    }
    
    if (practicesText) sections.push(`## ✨ Best Practices\n${practicesText}`);
  }

  // Prevention Strategies
  if (response.prevention_strategies) {
    let preventionText = '';
    
    if (response.prevention_strategies.code_review_checklist && Array.isArray(response.prevention_strategies.code_review_checklist)) {
      preventionText += `**Code Review Checklist:**\n${response.prevention_strategies.code_review_checklist.map((item: string, i: number) => `${i + 1}. ${item}`).join('\n')}\n\n`;
    }
    
    if (response.prevention_strategies.team_process_improvements && Array.isArray(response.prevention_strategies.team_process_improvements)) {
      preventionText += `**Team Process Improvements:**\n${response.prevention_strategies.team_process_improvements.map((improvement: string, i: number) => `${i + 1}. ${improvement}`).join('\n')}\n\n`;
    }
    
    if (preventionText) sections.push(`## 🛡️ Prevention Strategies\n${preventionText}`);
  }

  // Resolution Timeline
  if (response.estimated_resolution_time) {
    let timelineText = '';
    const timeline = response.estimated_resolution_time;
    
    if (timeline.immediate_fixes) timelineText += `**Immediate Fixes:** ${timeline.immediate_fixes}\n`;
    if (timeline.complete_resolution) timelineText += `**Complete Resolution:** ${timeline.complete_resolution}\n`;
    if (timeline.long_term_improvements) timelineText += `**Long-term Improvements:** ${timeline.long_term_improvements}\n`;
    
    if (timelineText) sections.push(`## ⏱️ Estimated Timeline\n${timelineText}`);
  }

  // Related Resources
  if (response.related_resources && Array.isArray(response.related_resources)) {
    let resourcesText = '';
    
    response.related_resources.forEach((resource: any, index: number) => {
      resourcesText += `${index + 1}. `;
      if (resource.title && resource.url) {
        resourcesText += `[${resource.title}](${resource.url})`;
        if (resource.relevance_score) resourcesText += ` (Relevance: ${resource.relevance_score}/100)`;
        if (resource.type) resourcesText += ` - ${resource.type}`;
      } else {
        resourcesText += JSON.stringify(resource);
      }
      resourcesText += '\n';
    });
    
    if (resourcesText) sections.push(`## 📚 Related Resources\n${resourcesText}`);
  }

  // Risk Assessment
  if (response.risk_assessment) {
    let riskText = '';
    
    if (response.risk_assessment.current_risk_level) {
      riskText += `**Current Risk Level:** ${response.risk_assessment.current_risk_level}\n\n`;
    }
    
    if (response.risk_assessment.risk_factors && Array.isArray(response.risk_assessment.risk_factors)) {
      riskText += `**Risk Factors:**\n${response.risk_assessment.risk_factors.map((factor: string, i: number) => `${i + 1}. ${factor}`).join('\n')}\n\n`;
    }
    
    if (response.risk_assessment.mitigation_priorities && Array.isArray(response.risk_assessment.mitigation_priorities)) {
      riskText += `**Mitigation Priorities:**\n${response.risk_assessment.mitigation_priorities.map((priority: string, i: number) => `${i + 1}. ${priority}`).join('\n')}\n`;
    }
    
    if (riskText) sections.push(`## ⚠️ Risk Assessment\n${riskText}`);
  }

  // Follow-up Recommendations
  if (response.follow_up_recommendations && Array.isArray(response.follow_up_recommendations)) {
    const followUpText = response.follow_up_recommendations.map((rec: string, i: number) => `${i + 1}. ${rec}`).join('\n');
    sections.push(`## 📋 Follow-up Recommendations\n${followUpText}`);
  }

  if (sections.length > 0) {
    return sections.join('\n\n');
  }

  // Fallback for any other response format
  return `## Expert Consultation Response\n\n\`\`\`json\n${JSON.stringify(response, null, 2)}\n\`\`\``;
}

/**
 * Creates a code snippet from a string of code
 */
export function createCodeSnippet(
  filepath: string,
  snippet: string,
  options: {
    lineRange?: string;
    language?: string;
    context?: string;
  } = {}
): CodeSnippet {
  return {
    filepath,
    snippet,
    line_range: options.lineRange,
    language: options.language || detectLanguage(filepath),
    context: options.context
  };
}

/**
 * Extracts a specific line range from file content
 */
export function extractLineRange(
  content: string,
  startLine: number,
  endLine: number
): string {
  const lines = content.split('\n');
  const extractedLines = lines.slice(startLine - 1, endLine);
  return extractedLines.join('\n');
}

/**
 * Reads a specific line range from a file and returns as CodeSnippet
 */
export async function readFileSnippet(
  filepath: string,
  startLine: number,
  endLine: number,
  options: {
    projectRoot?: string;
    context?: string;
  } = {}
): Promise<CodeSnippet> {
  const { projectRoot = process.cwd(), context } = options;
  
  try {
    const fullPath = path.resolve(projectRoot, filepath);
    const content = await fs.readFile(fullPath, 'utf-8');
    const snippet = extractLineRange(content, startLine, endLine);
    const relativePath = path.relative(projectRoot, fullPath);
    
    return {
      filepath: relativePath,
      snippet,
      line_range: `${startLine}-${endLine}`,
      language: detectLanguage(filepath),
      context
    };
  } catch (error: any) {
    throw new Error(`Failed to read snippet from ${filepath}:${startLine}-${endLine}: ${error.message}`);
  }
}

/**
 * Searches for a pattern in a file and returns surrounding context as snippet
 */
export async function findAndExtractSnippet(
  filepath: string,
  searchPattern: string | RegExp,
  options: {
    projectRoot?: string;
    contextLines?: number;
    context?: string;
  } = {}
): Promise<CodeSnippet | null> {
  const { projectRoot = process.cwd(), contextLines = 5, context } = options;
  
  try {
    const fullPath = path.resolve(projectRoot, filepath);
    const content = await fs.readFile(fullPath, 'utf-8');
    const lines = content.split('\n');
    const relativePath = path.relative(projectRoot, fullPath);
    
    let matchLineIndex = -1;
    
    // Find the pattern
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (typeof searchPattern === 'string') {
        if (line.includes(searchPattern)) {
          matchLineIndex = i;
          break;
        }
      } else {
        if (searchPattern.test(line)) {
          matchLineIndex = i;
          break;
        }
      }
    }
    
    if (matchLineIndex === -1) {
      return null; // Pattern not found
    }
    
    // Extract surrounding context
    const startLine = Math.max(0, matchLineIndex - contextLines);
    const endLine = Math.min(lines.length - 1, matchLineIndex + contextLines);
    const snippet = lines.slice(startLine, endLine + 1).join('\n');
    
    return {
      filepath: relativePath,
      snippet,
      line_range: `${startLine + 1}-${endLine + 1}`,
      language: detectLanguage(filepath),
      context: context || `Code around pattern: ${searchPattern}`
    };
  } catch (error: any) {
    throw new Error(`Failed to search and extract snippet from ${filepath}: ${error.message}`);
  }
}

/**
 * Prepares consultation request with specific code snippets
 */
export async function prepareSnippetConsultationRequest(
  issueDescription: string,
  snippets: CodeSnippet[],
  options: {
    projectContext?: string;
    errorLogs?: string;
    attemptedSolutions?: string[];
    urgencyLevel?: "low" | "medium" | "high" | "critical";
  } = {}
): Promise<ConsultationRequest> {
  // Collect environment info
  const environmentInfo = collectEnvironmentInfo();

  return {
    issue_description: issueDescription,
    code_snippets: snippets,
    project_context: options.projectContext || "Snippet-based consultation request",
    error_logs: options.errorLogs,
    attempted_solutions: options.attemptedSolutions || [],
    environment_info: environmentInfo,
    urgency_level: options.urgencyLevel || "medium"
  };
} 