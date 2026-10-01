# OpenAI-compatible review provider

The reviewer adapter uses the Chat Completions `POST /chat/completions` route and strictly parses one JSON-object response before applying the repository's existing specialist or adjudication validators. It is not a general client for every provider API. Endpoint/model support must be qualified against the selected service and model; compatibility labels alone do not establish support for a particular request field or output contract.

The default request remains unchanged: `response_format=json_schema`, `max_completion_tokens`, and `reasoning_effort=low`. Operators can set optional non-secret `LLM_RESPONSE_FORMAT`, `LLM_TOKEN_LIMIT_PARAMETER`, and `LLM_REASONING_EFFORT` values when creating the private runtime config. Supported values are:

| Setting | Values | Default |
|---|---|---|
| `LLM_RESPONSE_FORMAT` | `json_schema`, `json_object`, `prompted_json` | `json_schema` |
| `LLM_TOKEN_LIMIT_PARAMETER` | `max_completion_tokens`, `max_tokens` | `max_completion_tokens` |
| `LLM_REASONING_EFFORT` | `none`, `minimal`, `low`, `medium`, `high`, `xhigh`, `omit` | `low` |

`json_schema` sends Structured Outputs schema mode. On an endpoint that implements the compatible Structured Outputs contract for the selected model, the server constrains output to the supplied schema. Compatibility-branded endpoints may differ, so this server-side guarantee must not be assumed until qualified. `json_object` sends JSON mode and includes the same authoritative schema in the system instructions. `prompted_json` omits `response_format` and includes that schema in the system instructions. The latter two rely on local parsing and contract validation; they do not provide the server-side schema guarantee of Structured Outputs. All three are measured as exact serialized request bytes and subject to the same configured request, input, response, output-token, deadline, and task limits. An HTTP rejection fails the call; the adapter does not switch formats, token parameter, model, or endpoint and does not retry automatically.

`max_tokens` is retained as an explicit compatibility option, although the OpenAI API marks it deprecated and notes that it is incompatible with some reasoning models. Reasoning-effort values are finite and model-dependent; `omit` removes the field rather than guessing a substitute. An unsupported setting or endpoint/model combination should fail during a bounded qualification run and be corrected only through trusted operator configuration. No response-format or model fallback is inferred from an HTTP error.

The three optional variables are operator configuration, not task inputs. The config generator validates them against the finite allowlists before writing its private config files and never writes credential values. Do not put them in pull-request-controlled variables or artifacts. The OpenAI API documents the Chat Completions create operation, response-format modes, and token/reasoning fields; OpenAI-compatible implementations may implement a different subset. See the [Chat Completions API reference](https://developers.openai.com/api/reference/resources/chat/subresources/completions/methods/create) and [vLLM OpenAI-compatible server documentation](https://docs.vllm.ai/en/latest/serving/openai_compatible_server/).
