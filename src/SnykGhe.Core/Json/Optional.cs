using System.Text.Json.Serialization;

namespace SnykGhe.Core.Json
{
    /// <summary>
    /// A JSON member that carries whether it was present in the payload, distinct from its value. PATCH
    /// semantics need this three-way distinction: an absent member means "leave unchanged", an explicit
    /// <c>null</c> means "clear", and any other value means "set to this". Because System.Text.Json only
    /// invokes a converter for members physically present in the JSON, an absent member leaves this at its
    /// default — <see cref="IsSpecified"/> == <see langword="false"/>.
    /// </summary>
    [JsonConverter(typeof(OptionalJsonConverterFactory))]
    public readonly struct Optional<T>
    {
        public Optional(T? value)
        {
            IsSpecified = true;
            Value = value;
        }

        /// <summary>True when the member was present in the JSON payload; its <see cref="Value"/> may still be null.</summary>
        public bool IsSpecified { get; }

        /// <summary>The supplied value, or default/null when the member was absent or explicitly null.</summary>
        public T? Value { get; }
    }
}
