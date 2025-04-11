<?php
/**
 * Implements the `wp audit-files` command.
 *
 * Finds all PHP files in themes and plugins, splits them into manageable
 * chunks, sends each chunk to the Google Gemini API for review, and
 * compiles the results.
 */

if ( ! class_exists( 'WP_CLI' ) ) {
    return;
}

/**
 * Audits theme and plugin PHP files using Google Gemini with payload chunking.
 */
class Audit_Files_Command extends WP_CLI_Command {

    /**
     * Maximum payload size in bytes (e.g., ~1.9MB).
     */
    private const MAX_PAYLOAD_CHUNK_SIZE = 1900000;

    /**
     * Delay in seconds between consecutive API calls to avoid rate limiting.
     */
    private const API_CALL_DELAY = 5;

    /**
     * Primary Gemini model to use for analysis.
     */
    private const PRIMARY_MODEL = 'gemini-2.5-pro-exp-03-25'; // Your preferred Pro model

    /**
     * Fallback Gemini model to use if the primary model hits quota limits (429).
     * Using gemini-1.5-flash-latest as a common, efficient alternative.
     */
    private const FALLBACK_MODEL = 'gemini-1.5-flash-latest';

    // Store API key and other request parameters as properties for easier access
    private $api_key;
    private $timeout;
    private $api_prompt;
    private $responseSchema;
    private $custom_prompt;
    private $ignored_directories = [];

    /**
     * Audits theme and plugin PHP files using Google Gemini.
     *
     * Scans all themes and plugins by default. If --themes or --plugins are
     * provided, only the specified items will be scanned. Splits large sets
     * of files into chunks under ~2MB, makes separate API calls for each chunk,
     * and compiles the results. Attempts to get structured JSON output from
     * the API and display it as a table.
     *
     * ## OPTIONS
     *
     * [--skip-api-call]
     * : Only find files and report the number of chunks, do not make API calls.
     *   This is implicitly true if --output is used.
     *
     * [--api-key=<key>]
     * : Google Gemini API Key. If not provided, it will try to read the GEMINI_API_KEY environment variable.
     *
     * [--timeout=<seconds>]
     * : Timeout in seconds for *each* API request. Defaults to 300.
     *
     * [--themes=<themes>]
     * : Comma-separated list of theme slugs (directory names) to include.
     *   If provided, only these themes (and any specified plugins) will be scanned.
     *
     * [--plugins=<plugins>]
     * : Comma-separated list of plugin slugs (directory names) to include.
     *   If provided, only these plugins (and any specified themes) will be scanned.
     *
     * [--custom-prompt=<prompt>]
     * : Custom prompt to use for the API analysis. Replaces the default prompt.
     *
     * [--output=<filename>]
     * : Output the combined payload content to the specified file (e.g., payload.txt)
     *   instead of sending it to the API. This skips the API call process.
     *   Defaults to 'payload.txt' if the flag is provided without a value.
     *
     * [--ignore-directories=<dirs>]
     * : Comma-separated list of directory paths (relative to wp-content, e.g.,
     *   "plugins/some-plugin/vendor/,themes/my-theme/node_modules/") to exclude
     *   from the payload.
     *
     * ## EXAMPLES
     *
     *     # Scan ALL themes/plugins, chunk payloads, call API, display table
     *     wp audit-files --api-key=YOUR_API_KEY_HERE
     *
     *     # Only find files and show how many chunks would be created
     *     wp audit-files --skip-api-call
     *
     *     # Scan specific themes/plugins ONLY, chunk, call API
     *     wp audit-files --themes=twentytwentyfour --plugins=akismet --api-key=YOUR_KEY
     *
     *     # Scan with a custom prompt
     *     wp audit-files --api-key=YOUR_KEY --custom-prompt="Focus only on SQL injection vulnerabilities in the following files:"
     *
     *     # Scan specific plugin, ignoring its vendor directory, and output payload to file
     *     wp audit-files --plugins=my-plugin --ignore-directories="plugins/my-plugin/vendor/" --output=my-plugin-payload.txt
     *
     *     # Scan all but ignore specific directories, skip API call
     *     wp audit-files --ignore-directories="plugins/woocommerce/packages/,plugins/jetpack/_inc/lib/" --skip-api-call
     *
     * @when after_wp_load
     */
    public function __invoke( $args, $assoc_args ) {
        // --- Argument Parsing ---
        $skip_api_call = WP_CLI\Utils\get_flag_value( $assoc_args, 'skip-api-call', false );
        $this->api_key = WP_CLI\Utils\get_flag_value( $assoc_args, 'api-key', null );
        $this->timeout = WP_CLI\Utils\get_flag_value( $assoc_args, 'timeout', 300 );
        $this->custom_prompt = WP_CLI\Utils\get_flag_value( $assoc_args, 'custom-prompt', null );
        $selected_themes_str = WP_CLI\Utils\get_flag_value( $assoc_args, 'themes', '' );
        $selected_plugins_str = WP_CLI\Utils\get_flag_value( $assoc_args, 'plugins', '' );
        $output_filename = WP_CLI\Utils\get_flag_value( $assoc_args, 'output', null );
        $ignore_dirs_str = WP_CLI\Utils\get_flag_value( $assoc_args, 'ignore-directories', '' );

        // If --output is used, set filename to default if none provided, and force skip API call
        $output_payload = false;
        if ( $output_filename !== null ) {
            $output_payload = true;
            if ( $output_filename === true || $output_filename === '' ) { // Handle flag without value or empty value
                $output_filename = 'payload.txt';
            }
            $skip_api_call = true; // Outputting payload means we don't call the API
            WP_CLI::log( "Payload will be written to '{$output_filename}', API calls will be skipped." );
        }

        // --- API Key Validation (only if not skipping API) ---
        if ( ! $skip_api_call ) {
            if ( ! $this->api_key ) {
                $this->api_key = getenv( 'GEMINI_API_KEY' );
            }
            if ( ! $this->api_key ) {
                WP_CLI::error( "API Key not provided and API call not skipped. Please set the GEMINI_API_KEY environment variable or use the --api-key option, or use --skip-api-call / --output." );
                return;
            }
        }

        // --- Parse and Normalize Ignored Directories ---
        $this->parse_ignored_directories( $ignore_dirs_str );

        // --- Determine Paths to Scan ---
        $paths_to_scan = $this->determine_scan_paths( $selected_themes_str, $selected_plugins_str );
        if ( empty( $paths_to_scan ) ) {
             return;
        }

        // --- 1. Find PHP Files ---
        WP_CLI::log( "Searching for PHP files in designated paths..." );
        $php_files = $this->find_php_files( $paths_to_scan );
        if ( empty( $php_files ) ) {
            WP_CLI::warning( "No PHP files found in the specified directories." );
            return;
        }
        WP_CLI::log( "Found " . count( $php_files ) . " PHP files initially." );
        // Note: Filtering based on --ignore-directories happens during payload generation.

        // --- 2a. Handle --output: Generate Combined Payload and Save ---
        if ( $output_payload ) {
            WP_CLI::log( "Generating combined payload for output..." );
            $combined_payload = $this->generate_combined_payload( $php_files );
            $bytes_written = file_put_contents( $output_filename, $combined_payload );

            if ( $bytes_written !== false ) {
                WP_CLI::success( "Combined payload (excluding ignored directories) successfully written to: " . $output_filename . " (" . size_format( $bytes_written ) . ")" );
            } else {
                WP_CLI::error( "Failed to write combined payload to: " . $output_filename );
            }
            return; // Exit after writing payload
        }

        // --- 2b. Generate Payload Chunks (if not outputting) ---
        WP_CLI::log( "Generating payload chunks (max size per chunk: " . size_format( self::MAX_PAYLOAD_CHUNK_SIZE ) . ")..." );
        $payload_chunks = $this->generate_payload_chunks( $php_files );
        $chunk_count = count( $payload_chunks );

        if ( $chunk_count === 0 ) {
             WP_CLI::warning( "No payload chunks generated. This might happen if all files were empty, ignored, could not be read, or if individual files exceed the chunk size limit." );
             return;
        }
        WP_CLI::log( "Payload split into " . $chunk_count . " chunk(s) after filtering ignored directories." );

        // --- 3. Prepare for API Calls (if not skipped) ---
        if ( $skip_api_call ) {
            WP_CLI::log( "Skipping API calls as requested." );
            // We already logged chunk count above if applicable
            return;
        }

        WP_CLI::log( "Preparing API requests to Google Gemini for JSON output..." );

        // Define schema and prompt (moved to properties/setup)
        $this->setup_api_parameters();

        $all_issues = []; // Array to collect issues from all chunks
        $total_api_time = 0;
        $failed_chunks = 0;

        // --- 4. Loop Through Chunks and Process ---
        WP_CLI::log( "Starting API calls for {$chunk_count} chunk(s)..." );
        for ( $i = 0; $i < $chunk_count; $i++ ) {
            $chunk_num = $i + 1;
            $chunk_content = $payload_chunks[$i];

            WP_CLI::log( "Processing chunk {$chunk_num} of {$chunk_count}..." );

            $start_time = microtime( true );
            $chunk_results = $this->process_api_chunk( $chunk_content, $chunk_num, $chunk_count );
            $end_time = microtime( true );
            $duration = $end_time - $start_time;
            $total_api_time += $duration;

            WP_CLI::log( sprintf( "Chunk {$chunk_num}: Call completed in %.2f seconds.", $duration ) );

            if ( $chunk_results === false ) {
                // Error occurred and was logged within process_api_chunk
                $failed_chunks++;
            } elseif ( is_array( $chunk_results ) && ! empty( $chunk_results ) ) {
                WP_CLI::log( "Chunk {$chunk_num}: Received " . count( $chunk_results ) . " issue(s)." );
                $all_issues = array_merge( $all_issues, $chunk_results );
            } else {
                 WP_CLI::log( "Chunk {$chunk_num}: No issues reported by API for this chunk." );
            }

            // Add a delay before the next chunk's API call (unless it's the last one)
            if ( $chunk_num < $chunk_count && self::API_CALL_DELAY > 0 ) {
                WP_CLI::log( "Waiting " . self::API_CALL_DELAY . " second(s) before next API call..." );
                sleep( self::API_CALL_DELAY );
            }
        } // End for loop

        WP_CLI::log( sprintf( "All API calls attempted. Total API processing time: %.2f seconds.", $total_api_time ) );
        if ($failed_chunks > 0) {
            WP_CLI::warning("Failed to process {$failed_chunks} out of {$chunk_count} chunks. Results may be incomplete.");
        }

        // --- 5. Process Combined Results ---
        if ( ! empty( $all_issues ) ) {
            WP_CLI::log( "Sorting combined results by severity (High > Medium > Low > Info)..." );
            $this->sort_issues( $all_issues ); // Use a helper for sorting
        }

        // --- 6. Display Final Results ---
        if ( empty( $all_issues ) ) {
            if ($failed_chunks == 0) {
                WP_CLI::success( "Scan complete. No major issues reported by the API across all chunks." );
            } else {
                 WP_CLI::warning( "Scan complete, but some chunks failed. No issues reported in the successfully processed chunks." );
            }
        } else {
            WP_CLI::success( "Scan complete. Potential issues reported:" );
            $fields = ['file_path', 'severity', 'issue_description', 'code_snippet'];
             // Ensure null values that cause issues with table formatter are converted
            foreach ( $all_issues as $key => $issue ) {
                // Ensure 'code_snippet' exists, setting to '' if missing or null.
                if ( ! isset( $issue['code_snippet'] ) || is_null( $issue['code_snippet'] ) ) {
                    $all_issues[$key]['code_snippet'] = '';
                }
                 // Ensure file_path exists
                if ( ! isset( $issue['file_path'] ) || is_null( $issue['file_path'] ) ) {
                    $all_issues[$key]['file_path'] = '[Unknown Path]';
                }
                 // Ensure severity exists
                if ( ! isset( $issue['severity'] ) || is_null( $issue['severity'] ) ) {
                    $all_issues[$key]['severity'] = 'Unknown';
                }
                 // Ensure issue_description exists
                if ( ! isset( $issue['issue_description'] ) || is_null( $issue['issue_description'] ) ) {
                    $all_issues[$key]['issue_description'] = '[No Description]';
                }
            }
            WP_CLI\Utils\format_items( 'table', $all_issues, $fields );
        }

        // --- 7. Save Combined Results to File ---
        // Always attempt to save, even if empty, to indicate the process ran.
        $output_filename = 'all-issues.json';
        WP_CLI::log( "Attempting to save combined results to {$output_filename}..." );

        // Encode the array into a JSON string with pretty printing and unescaped slashes
        $json_output = json_encode(
            $all_issues,
            JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES
        );

        if ( $json_output === false ) {
            // Handle potential errors during JSON encoding
            WP_CLI::warning( "Failed to encode results to JSON: " . json_last_error_msg() );
        } else {
            // Write the JSON string to the file in the current directory
            if ( file_put_contents( $output_filename, $json_output ) !== false ) {
                // Use success message for successful save
                WP_CLI::success( "Successfully saved combined results to: " . $output_filename );
            } else {
                // Use warning for file writing failure
                WP_CLI::warning( "Failed to write results to file: " . $output_filename );
            }
        }

    }

    /**
     * Parses the comma-separated string of ignored directories and normalizes them.
     *
     * @param string $ignore_dirs_str Comma-separated directory paths relative to wp-content.
     */
    private function parse_ignored_directories( $ignore_dirs_str ) {
        $this->ignored_directories = [];
        if ( ! empty( $ignore_dirs_str ) ) {
            $raw_ignored = array_map( 'trim', explode( ',', $ignore_dirs_str ) );
            $count = 0;
            foreach ( $raw_ignored as $dir ) {
                if ( empty( $dir ) ) continue;
                // Normalize separators to '/' for comparison
                $normalized_dir = str_replace( '\\', '/', $dir );
                // Remove leading/trailing slashes for consistency
                $normalized_dir = trim( $normalized_dir, '/' );
                // Add back leading and trailing slash for prefix matching
                // Ensure it starts relative to wp-content (i.e., starts with themes/ or plugins/)
                if ( ! empty( $normalized_dir ) ) {
                    $this->ignored_directories[] = '/' . $normalized_dir . '/';
                    $count++;
                }
            }
            if ( $count > 0 ) {
                WP_CLI::log( "Ignoring files within {$count} specified director(y/ies)." );
                WP_CLI::debug( "Normalized ignored directories: " . implode( ', ', $this->ignored_directories ) );
            }
        }
    }

    /**
     * Checks if a given file path should be ignored based on the --ignore-directories list.
     *
     * @param string $file_path Absolute path to the file.
     * @return bool True if the file should be ignored, false otherwise.
     */
    private function is_file_ignored( $file_path ) {
        if ( empty( $this->ignored_directories ) ) {
            return false;
        }

        $wp_content_path_len = strlen( WP_CONTENT_DIR );
        $relative_path = substr( $file_path, $wp_content_path_len );
        // Normalize separators to '/'
        $normalized_relative_path = str_replace( '\\', '/', $relative_path );
        // Ensure leading slash
        if ( strpos( $normalized_relative_path, '/' ) !== 0 ) {
            $normalized_relative_path = '/' . $normalized_relative_path;
        }

        foreach ( $this->ignored_directories as $ignored_dir ) {
            // Check if the normalized relative path starts with the normalized ignored directory
            if ( strpos( $normalized_relative_path, $ignored_dir ) === 0 ) {
                WP_CLI::debug( "Ignoring file due to rule '{$ignored_dir}': {$normalized_relative_path}" );
                return true;
            }
        }

        return false;
    }

    /**
     * Sets up API URL, prompt, and response schema.
     */
    private function setup_api_parameters() {

        $this->responseSchema = [
            'type' => 'ARRAY',
            'description' => 'List of potential issues found in the PHP files.',
            'items' => [
                'type' => 'OBJECT',
                'properties' => [
                    'file_path' => ['type' => 'STRING', 'description' => 'Relative path (e.g., /themes/my-theme/functions.php)'],
                    'issue_description' => ['type' => 'STRING', 'description' => 'Description of the potential issue.'],
                    'severity' => ['type' => 'STRING', 'description' => 'Estimated severity (High, Medium, Low, Info).'],
                    'code_snippet' => ['type' => 'STRING', 'description' => 'Optional code snippet.', 'nullable' => true]
                ],
                'required' => ['file_path', 'issue_description', 'severity']
            ]
        ];

        // Set the default prompt
        $this->api_prompt = <<<PROMPT
Review the following WordPress theme and plugin PHP files provided in the payload.
Identify potential major issues such as malware patterns, significant security vulnerabilities (like SQL injection, XSS, insecure file handling), or deprecated code usage with security implications.
If no major issues are identified, then skip without any response.

Begin payload here:

PROMPT;

        // Check if a custom prompt was provided
        if ( ! is_null( $this->custom_prompt ) && is_string( $this->custom_prompt ) && ! empty( trim( $this->custom_prompt ) ) ) {
            WP_CLI::log( "Using custom prompt provided via --custom-prompt." );
            // Use the custom prompt with the required structure
            $this->api_prompt = <<<PROMPT
{$this->custom_prompt}

Begin payload here:

PROMPT;
        }
    }

    /**
     * Processes a single payload chunk via the Gemini API.
     *
     * @param string $chunk_content The payload content for this chunk.
     * @param int    $chunk_num     The number of this chunk (for logging).
     * @param int    $chunk_count   The total number of chunks (for logging).
     * @return array|false An array of issues found, an empty array if none, or false on failure.
     */
    private function process_api_chunk( $chunk_content, $chunk_num, $chunk_count ) {
        $api_payload_text = $this->api_prompt . $chunk_content;

        $api_data = [
            'contents' => [ [ 'parts' => [ [ 'text' => $api_payload_text ] ] ] ],
            'generationConfig' => [
                'responseMimeType' => 'application/json',
                'responseSchema' => $this->responseSchema
            ]
        ];

        $json_data = json_encode( $api_data );

        if ( json_last_error() !== JSON_ERROR_NONE ) {
             WP_CLI::warning( "Chunk {$chunk_num}/{$chunk_count}: Failed to encode API data as JSON: " . json_last_error_msg() . ". Skipping." );
             return false;
        }

        $request_args = [
            'method'  => 'POST',
            'headers' => [ 'Content-Type' => 'application/json' ],
            'body'    => $json_data,
            'timeout' => absint( $this->timeout ),
        ];

        // --- Attempt 1: Primary Model ---
        $current_model = self::PRIMARY_MODEL;
        $api_url = "https://generativelanguage.googleapis.com/v1beta/models/{$current_model}:generateContent?key=" . $this->api_key;

        WP_CLI::debug( "Chunk {$chunk_num}/{$chunk_count}: Sending request to {$api_url} (timeout: {$this->timeout}s)..." );
        $response = wp_remote_post( $api_url, $request_args );

        // --- Process API Response ---
        if ( is_wp_error( $response ) ) {
            $error_message = $response->get_error_message();
            WP_CLI::warning( "Chunk {$chunk_num}/{$chunk_count}: API request failed (WP_Error): " . $error_message . ". Skipping." );
            return false;
        }

        $response_code = wp_remote_retrieve_response_code( $response );
        $response_body = wp_remote_retrieve_body( $response );
        WP_CLI::debug( "Chunk {$chunk_num}/{$chunk_count}: API Response Code: " . $response_code );

        // --- Check for 429 and Attempt Fallback ---
        if ( $response_code === 429 ) {
            WP_CLI::warning( "Chunk {$chunk_num}/{$chunk_count}: Received 429 (Quota Exceeded) for primary model ({$current_model}). Falling back to " . self::FALLBACK_MODEL . "..." );
            WP_CLI::debug( "Chunk {$chunk_num}/{$chunk_count}: Raw 429 Response Body:\n" . $response_body ); // Log the 429 error details

            // --- Attempt 2: Fallback Model ---
            $current_model = self::FALLBACK_MODEL; // Update model for logging/URL
            $api_url = "https://generativelanguage.googleapis.com/v1beta/models/{$current_model}:generateContent?key=" . $this->api_key;

            sleep(1); // Short delay before retry

            WP_CLI::debug( "Chunk {$chunk_num}/{$chunk_count}: Attempting fallback model ({$current_model}) via {$api_url} (timeout: {$this->timeout}s)..." );
            $response = wp_remote_post( $api_url, $request_args ); // Re-use $request_args

            // Check fallback response for WP_Error
            if ( is_wp_error( $response ) ) {
                $error_message = $response->get_error_message();
                WP_CLI::warning( "Chunk {$chunk_num}/{$chunk_count}: Fallback API request failed (WP_Error): " . $error_message . ". Skipping." );
                return false;
            }

            // Get fallback response details
            $response_code = wp_remote_retrieve_response_code( $response );
            $response_body = wp_remote_retrieve_body( $response );
            WP_CLI::debug( "Chunk {$chunk_num}/{$chunk_count}: Fallback model ({$current_model}) response code: " . $response_code );

            // If fallback *also* fails (any error), then give up for this chunk
            if ( $response_code < 200 || $response_code >= 300 ) {
                 WP_CLI::warning( "Chunk {$chunk_num}/{$chunk_count}: Fallback API request also returned non-success status code: " . $response_code . ". Skipping." );
                 WP_CLI::debug( "Chunk {$chunk_num}/{$chunk_count}: Raw Fallback Response Body:\n" . $response_body );
                 return false;
            }

            // Fallback succeeded! Log it. Processing continues below.
            WP_CLI::log( "Chunk {$chunk_num}/{$chunk_count}: Fallback model ({$current_model}) request successful." );

        } elseif ( $response_code < 200 || $response_code >= 300 ) {
             // Handle non-429 errors from the primary model
             WP_CLI::warning( "Chunk {$chunk_num}/{$chunk_count}: API request returned non-success status code: " . $response_code . ". Skipping." );
             WP_CLI::debug( "Chunk {$chunk_num}/{$chunk_count}: Raw API Response Body:\n" . $response_body );
             return false;
        }

        // Decode main API response
        $api_response_data = json_decode( $response_body, true );
        if ( json_last_error() !== JSON_ERROR_NONE ) {
            WP_CLI::warning( "Chunk {$chunk_num}/{$chunk_count}: Failed to decode the main API JSON response: " . json_last_error_msg() . ". Skipping." );
            WP_CLI::debug( "Chunk {$chunk_num}/{$chunk_count}: Raw API Response Body:\n" . $response_body );
            return false;
        }

        // Extract the nested JSON *string*
        $issues_json_string = $api_response_data['candidates'][0]['content']['parts'][0]['text'] ?? null;

        // Check for safety ratings block or missing text part
        if ( $issues_json_string === null ) {
             if (isset($api_response_data['candidates'][0]['finishReason']) && $api_response_data['candidates'][0]['finishReason'] === 'SAFETY') {
                 WP_CLI::warning( "Chunk {$chunk_num}/{$chunk_count}: API response blocked due to safety settings. Skipping." );
                 WP_CLI::debug( "Chunk {$chunk_num}/{$chunk_count}: Decoded API Response Structure:\n" . print_r( $api_response_data, true ) );
                 return false;
             }
             // Handle cases where 'text' might be missing for other reasons (e.g., API error structure, or maybe no issues found and API returns empty content)
             // Check if the response indicates no content was generated intentionally
             if (isset($api_response_data['candidates'][0]['finishReason']) && $api_response_data['candidates'][0]['finishReason'] === 'STOP' && empty($api_response_data['candidates'][0]['content'])) {
                 WP_CLI::debug( "Chunk {$chunk_num}/{$chunk_count}: API indicated successful completion but no content part (likely no issues found)." );
                 return []; // Return empty array, indicating no issues found for this chunk
             }

             WP_CLI::warning( "Chunk {$chunk_num}/{$chunk_count}: Could not find the expected result text in the API response structure. Skipping." );
             WP_CLI::debug( "Chunk {$chunk_num}/{$chunk_count}: Decoded API Response Structure:\n" . print_r( $api_response_data, true ) );
             return false;
        }

        // --- Start: Clean the extracted string ---
        $original_for_debug = $issues_json_string; // Keep original for debug

        // Find the first opening bracket ([ or {)
        $first_bracket = strpos( $issues_json_string, '[' );
        $first_curly = strpos( $issues_json_string, '{' );
        $start_pos = false;

        if ( $first_bracket !== false && $first_curly !== false ) {
            $start_pos = min( $first_bracket, $first_curly );
        } elseif ( $first_bracket !== false ) {
            $start_pos = $first_bracket;
        } elseif ( $first_curly !== false ) {
            $start_pos = $first_curly;
        }

        // Find the last closing bracket (] or })
        $last_bracket = strrpos( $issues_json_string, ']' );
        $last_curly = strrpos( $issues_json_string, '}' );
        $end_pos = false;

        if ( $last_bracket !== false && $last_curly !== false ) {
            $end_pos = max( $last_bracket, $last_curly );
        } elseif ( $last_bracket !== false ) {
            $end_pos = $last_bracket;
        } elseif ( $last_curly !== false ) {
            $end_pos = $last_curly;
        }

        if ( $start_pos !== false && $end_pos !== false && $end_pos >= $start_pos ) {
            // Extract the substring from the first opening bracket to the last closing bracket
            $issues_json_string = substr( $issues_json_string, $start_pos, $end_pos - $start_pos + 1 );
            WP_CLI::debug( "Chunk {$chunk_num}/{$chunk_count}: Extracted potential JSON between first bracket (pos {$start_pos}) and last bracket (pos {$end_pos})." );
        } else {
            // If we couldn't find a valid start/end bracket pair, maybe the response is empty or just text
            // Check if the original string is empty or effectively empty after trimming
            if (trim($original_for_debug) === '') {
                WP_CLI::debug( "Chunk {$chunk_num}/{$chunk_count}: API response text content was empty. Assuming no issues reported." );
                return []; // Treat as no issues found
            }
            WP_CLI::warning( "Chunk {$chunk_num}/{$chunk_count}: Could not reliably locate JSON start/end brackets in the API response. Skipping." );
            WP_CLI::debug( "Chunk {$chunk_num}/{$chunk_count}: Original text content received:\n" . $original_for_debug );
            return false;
        }
        // --- End: Clean the extracted string ---

        // Decode the actual issues list
        $chunk_issues_array = json_decode( $issues_json_string, true );
        if ( json_last_error() !== JSON_ERROR_NONE ) {
            // Before failing, check if the cleaned string is just "[]" or "{}" which decodes to empty array/object
            if (trim($issues_json_string) === '[]' || trim($issues_json_string) === '{}') {
                 WP_CLI::debug( "Chunk {$chunk_num}/{$chunk_count}: API returned an empty JSON array/object. Assuming no issues reported." );
                 return []; // Treat as no issues found
            }
            WP_CLI::warning( "Chunk {$chunk_num}/{$chunk_count}: API returned text that wasn't the expected valid JSON array after cleaning: " . json_last_error_msg() . ". Skipping." );
            WP_CLI::debug( "Chunk {$chunk_num}/{$chunk_count}: Received text content (cleaned, expected JSON string):\n" . $issues_json_string );
            WP_CLI::debug( "Chunk {$chunk_num}/{$chunk_count}: Original text content received:\n" . $original_for_debug );
            return false;
        }

        if ( ! is_array( $chunk_issues_array ) ) {
             WP_CLI::warning( "Chunk {$chunk_num}/{$chunk_count}: API returned valid JSON, but it wasn't the expected array structure. Skipping." );
             WP_CLI::debug( "Chunk {$chunk_num}/{$chunk_count}: Received JSON structure:\n" . print_r( $chunk_issues_array, true ) );
             return false;
        }

        // Success! Return the array of issues (could be empty)
        return $chunk_issues_array;
    }

    /**
     * Determines the absolute paths to scan based on flags.
     *
     * @param string $selected_themes_str Comma-separated theme slugs.
     * @param string $selected_plugins_str Comma-separated plugin slugs.
     * @return array List of absolute directory paths to scan.
     */
    private function determine_scan_paths( $selected_themes_str, $selected_plugins_str ) {
        $paths_to_scan = [];
        $scan_only_selected = ! empty( $selected_themes_str ) || ! empty( $selected_plugins_str );

        if ( $scan_only_selected ) {
            WP_CLI::log( "Scanning selected paths based on --themes/--plugins flags." );
             if ( ! empty( $selected_themes_str ) ) {
                $selected_themes = array_map( 'trim', explode( ',', $selected_themes_str ) );
                foreach ( $selected_themes as $theme_slug ) {
                    $path = WP_CONTENT_DIR . '/themes/' . $theme_slug;
                    if ( is_dir( $path ) ) {
                        $paths_to_scan[] = $path;
                        WP_CLI::debug( "Adding theme path: " . $path );
                    } else {
                        WP_CLI::warning( "Specified theme directory not found: " . $path );
                    }
                }
            }

            if ( ! empty( $selected_plugins_str ) ) {
                $selected_plugins = array_map( 'trim', explode( ',', $selected_plugins_str ) );
                foreach ( $selected_plugins as $plugin_slug ) {
                    $path = WP_CONTENT_DIR . '/plugins/' . $plugin_slug;
                     if ( is_dir( $path ) ) {
                        $paths_to_scan[] = $path;
                         WP_CLI::debug( "Adding plugin path: " . $path );
                    } else {
                        $single_file_path = WP_CONTENT_DIR . '/plugins/' . $plugin_slug . '.php';
                        if ( file_exists( $single_file_path ) ) {
                             WP_CLI::warning( "Specified plugin seems to be a single file, not a directory. Scanning directories only. Skipping: " . $plugin_slug . ".php" );
                        } else {
                            WP_CLI::warning( "Specified plugin directory not found: " . $path );
                        }
                    }
                }
            }

            if ( empty( $paths_to_scan ) ) {
                 WP_CLI::warning( "No valid theme or plugin directories found based on selection. No files to scan." );
            }
        } else {
            WP_CLI::log( "Scanning all themes and plugins (default behavior)." );
            $paths_to_scan = [
                WP_CONTENT_DIR . '/themes',
                WP_CONTENT_DIR . '/plugins',
            ];
             WP_CLI::debug( "Adding default theme path: " . $paths_to_scan[0] );
             WP_CLI::debug( "Adding default plugin path: " . $paths_to_scan[1] );
        }
        return $paths_to_scan;
    }

    /**
     * Finds all .php files recursively within specified directories.
     * Does NOT filter based on --ignore-directories here.
     *
     * @param array $paths_to_scan List of absolute directory paths to scan.
     * @return array List of full file paths.
     */
    private function find_php_files( $paths_to_scan ) {
        $files = [];
        foreach ( $paths_to_scan as $path ) {
            if ( ! is_dir( $path ) ) continue;
            try {
                $iterator = new RecursiveIteratorIterator(
                    new RecursiveDirectoryIterator( $path, RecursiveDirectoryIterator::SKIP_DOTS | RecursiveDirectoryIterator::FOLLOW_SYMLINKS ), // Added FOLLOW_SYMLINKS
                    RecursiveIteratorIterator::SELF_FIRST
                );
                foreach ( $iterator as $fileinfo ) {
                    // Check if it's a readable file with a .php extension
                    if ( $fileinfo->isFile() && $fileinfo->isReadable() && strtolower( $fileinfo->getExtension() ) === 'php' ) {
                        $real_path = $fileinfo->getRealPath();
                        // Ensure realpath() didn't fail (e.g., broken symlink)
                        if ($real_path !== false) {
                            $files[] = $real_path;
                        } else {
                             WP_CLI::debug( "Skipping unresolvable path: " . $fileinfo->getPathname() );
                        }
                    }
                }
            } catch ( UnexpectedValueException $e ) {
                // This often happens with permission errors or unreadable directories/symlinks
                WP_CLI::warning( "Could not fully access path or encountered issue: " . $path . " - " . $e->getMessage() );
            } catch ( Exception $e ) {
                 WP_CLI::warning( "Error scanning path: " . $path . " - " . $e->getMessage() );
            }
        }
        // Return unique paths, as symlinks might cause duplicates if not handled carefully
        return array_unique( $files );
    }

    /**
     * Generates payload content chunks from a list of files, respecting size limits
     * and ignoring specified directories.
     *
     * @param array $files List of file paths.
     * @return array An array of strings, each representing a payload chunk.
     */
    private function generate_payload_chunks( $files ) {
        $chunks = [];
        $current_chunk = '';
        $current_chunk_size = 0;
        $wp_content_path_len = strlen( WP_CONTENT_DIR );
        $file_separator = "\n\n";
        $file_separator_len = strlen( $file_separator );
        $included_file_count = 0;
        $ignored_file_count = 0;

        foreach ( $files as $file_path ) {
            // Check if file should be ignored BEFORE reading content
            if ( $this->is_file_ignored( $file_path ) ) {
                $ignored_file_count++;
                continue;
            }

            $relative_path = substr( $file_path, $wp_content_path_len );
            // Normalize separators and ensure leading slash for header
            $normalized_relative_path = str_replace( '\\', '/', $relative_path );
            if ( strpos( $normalized_relative_path, '/' ) !== 0 ) {
                 $normalized_relative_path = '/' . $normalized_relative_path;
            }
            $file_header = "--- File: wp-content" . $normalized_relative_path . " ---\n";
            $file_header_len = strlen( $file_header );

            $content = file_get_contents( $file_path );
            if ( $content === false ) {
                WP_CLI::warning( "Could not read file: " . $file_path . ". Skipping." );
                continue;
            }
            $content = str_replace( "\0", '', $content ); // Remove null bytes
            $content_len = strlen( $content );

            // Calculate size added by this file (including separator if needed)
            $added_size = ($current_chunk_size > 0 ? $file_separator_len : 0) + $file_header_len + $content_len;

            // Check if the file *itself* is too large
            if ( $file_header_len + $content_len > self::MAX_PAYLOAD_CHUNK_SIZE ) {
                 WP_CLI::warning( "File wp-content{$normalized_relative_path} (size: " . size_format($content_len) . ") exceeds the maximum chunk size limit (" . size_format(self::MAX_PAYLOAD_CHUNK_SIZE) . ") and will be skipped." );
                 continue;
            }

            // Check if adding this file exceeds the chunk limit
            if ( $current_chunk_size > 0 && ($current_chunk_size + $added_size) > self::MAX_PAYLOAD_CHUNK_SIZE ) {
                // Finalize the current chunk
                $chunks[] = $current_chunk;
                WP_CLI::debug( "Chunk created, size: " . size_format($current_chunk_size) );
                // Start a new chunk with the current file
                $current_chunk = $file_header . $content;
                $current_chunk_size = $file_header_len + $content_len; // Reset size for the new chunk
                $included_file_count++;
            } else {
                // Add to the current chunk
                if ( $current_chunk_size > 0 ) {
                    $current_chunk .= $file_separator;
                }
                $current_chunk .= $file_header . $content;
                $current_chunk_size += $added_size; // Update size correctly
                $included_file_count++;
            }
        }

        // Add the last remaining chunk if it has content
        if ( $current_chunk_size > 0 ) {
            $chunks[] = $current_chunk;
             WP_CLI::debug( "Final chunk created, size: " . size_format($current_chunk_size) );
        }

        if ( $ignored_file_count > 0 ) {
            WP_CLI::log( "Ignored {$ignored_file_count} file(s) based on --ignore-directories rules." );
        }
        WP_CLI::log( "Included {$included_file_count} file(s) in the generated payload/chunks." );


        return $chunks;
    }

     /**
     * Generates a single combined payload string from a list of files,
     * ignoring specified directories. Used for the --output flag.
     *
     * @param array $files List of file paths.
     * @return string The combined payload content.
     */
    private function generate_combined_payload( $files ) {
        $combined_payload = '';
        $wp_content_path_len = strlen( WP_CONTENT_DIR );
        $file_separator = "\n\n";
        $included_file_count = 0;
        $ignored_file_count = 0;

        foreach ( $files as $file_path ) {
            // Check if file should be ignored BEFORE reading content
            if ( $this->is_file_ignored( $file_path ) ) {
                $ignored_file_count++;
                continue;
            }

            $relative_path = substr( $file_path, $wp_content_path_len );
            // Normalize separators and ensure leading slash for header
            $normalized_relative_path = str_replace( '\\', '/', $relative_path );
            if ( strpos( $normalized_relative_path, '/' ) !== 0 ) {
                 $normalized_relative_path = '/' . $normalized_relative_path;
            }
            $file_header = "--- File: wp-content" . $normalized_relative_path . " ---\n";

            $content = file_get_contents( $file_path );
            if ( $content === false ) {
                WP_CLI::warning( "Could not read file: " . $file_path . ". Skipping." );
                continue;
            }
            $content = str_replace( "\0", '', $content ); // Remove null bytes

            // Add separator if not the first file
            if ( ! empty( $combined_payload ) ) {
                $combined_payload .= $file_separator;
            }

            $combined_payload .= $file_header . $content;
            $included_file_count++;
        }

        if ( $ignored_file_count > 0 ) {
            WP_CLI::log( "Ignored {$ignored_file_count} file(s) based on --ignore-directories rules." );
        }
        WP_CLI::log( "Included {$included_file_count} file(s) in the combined payload." );

        return $combined_payload;
    }


    /**
     * Sorts the issues array by severity.
     *
     * @param array &$issues_array The array of issues to sort (passed by reference).
     */
    private function sort_issues( &$issues_array ) {
         $severity_order = [ 'high' => 1, 'medium' => 2, 'low' => 3, 'info' => 4, 'unknown' => 5 ]; // Added unknown
         $default_priority = 6; // Default for completely missing severity

         usort( $issues_array, function( $a, $b ) use ( $severity_order, $default_priority ) {
             $sev_a = strtolower( $a['severity'] ?? '' );
             $sev_b = strtolower( $b['severity'] ?? '' );
             $priority_a = $severity_order[ $sev_a ] ?? $default_priority;
             $priority_b = $severity_order[ $sev_b ] ?? $default_priority;

             // Primary sort by severity
             if ($priority_a !== $priority_b) {
                 return $priority_a <=> $priority_b;
             }

             // Secondary sort by file path if severity is the same
             $path_a = $a['file_path'] ?? '';
             $path_b = $b['file_path'] ?? '';
             return strcmp($path_a, $path_b);
         } );
    }
}

// Register the command
WP_CLI::add_command( 'audit-files', 'Audit_Files_Command' );
