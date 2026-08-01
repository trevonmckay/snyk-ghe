using System.Text.Json;
using System.Text.Json.Serialization;

namespace SnykGhe.Core.Json
{
    /// <summary>
    /// Serializes <see cref="Optional{T}"/> as its underlying value. On read, the converter is only ever
    /// reached for members present in the JSON, so it always produces an <see cref="Optional{T}.IsSpecified"/>
    /// == <see langword="true"/> result — including for an explicit <c>null</c>, which System.Text.Json passes
    /// through because <see cref="Optional{T}"/> is a value type (converters for value types handle null by
    /// default). An absent member never reaches the converter and stays <c>default</c> (not specified).
    /// </summary>
    public sealed class OptionalJsonConverterFactory : JsonConverterFactory
    {
        public override bool CanConvert(Type typeToConvert) =>
            typeToConvert.IsGenericType && typeToConvert.GetGenericTypeDefinition() == typeof(Optional<>);

        public override JsonConverter CreateConverter(Type typeToConvert, JsonSerializerOptions options)
        {
            var valueType = typeToConvert.GetGenericArguments()[0];
            var converterType = typeof(OptionalConverter<>).MakeGenericType(valueType);
            return (JsonConverter)Activator.CreateInstance(converterType)!;
        }

        private sealed class OptionalConverter<T> : JsonConverter<Optional<T>>
        {
            public override Optional<T> Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
            {
                var value = JsonSerializer.Deserialize<T>(ref reader, options);
                return new Optional<T>(value);
            }

            public override void Write(Utf8JsonWriter writer, Optional<T> value, JsonSerializerOptions options)
            {
                JsonSerializer.Serialize(writer, value.Value, options);
            }
        }
    }
}
