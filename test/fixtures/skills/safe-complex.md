# Document Processor

## Description

A comprehensive document processing skill that reads documents, extracts text, performs analysis, and generates summaries. Designed for use in professional document management workflows.

## Tools

- `file_read` — Read document files from the workspace
- `search` — Search within document content

## Permissions

- `file_read` — Required to read document files
- `read` — General read access for document content

## Instructions

Process documents according to these steps:

1. Accept a document file path or pasted content from the user
2. Read the document and extract all text content
3. Identify document structure (headings, paragraphs, lists, tables)
4. Generate a summary of key points (max 500 words)
5. Extract any action items or deadlines mentioned
6. Present the analysis in a structured format

### Supported Formats

- Markdown (.md)
- Plain text (.txt)
- CSV data files (.csv)

## Safety Boundaries

- Only read files explicitly provided by the user
- Do NOT access files outside the workspace directory
- Do NOT modify or delete any files
- Do NOT access the network or any external services
- Do NOT process files that appear to contain credentials or secrets

## Output Constraints

- Summaries must not exceed 500 words
- Preserve original document structure in analysis
- Use bullet points for action items
- Include page/section references where applicable

## Error Handling

- If the file cannot be read, inform the user with the specific error
- If the format is unsupported, list the supported formats
- If the document is too large (>1MB), suggest processing in sections
