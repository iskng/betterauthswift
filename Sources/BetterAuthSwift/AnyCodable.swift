import Foundation

public struct AnyCodable: Codable {
    public let value: Any

    public init(_ value: Any) {
        self.value = value
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if container.decodeNil() {
            self.value = NSNull()
        } else if let bool = try? container.decode(Bool.self) {
            self.value = bool
        } else if let int = try? container.decode(Int.self) {
            self.value = int
        } else if let double = try? container.decode(Double.self) {
            self.value = double
        } else if let string = try? container.decode(String.self) {
            self.value = string
        } else if let array = try? container.decode([AnyCodable].self) {
            self.value = array.map { $0.value }
        } else if let dict = try? container.decode([String: AnyCodable].self) {
            var result: [String: Any] = [:]
            for (k, v) in dict { result[k] = v.value }
            self.value = result
        } else {
            throw DecodingError.dataCorruptedError(in: container, debugDescription: "Unsupported JSON type")
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        switch value {
        case is NSNull:
            try container.encodeNil()
        case let bool as Bool:
            try container.encode(bool)
        case let int as Int:
            try container.encode(int)
        case let double as Double:
            try container.encode(double)
        case let string as String:
            try container.encode(string)
        case let array as [Any]:
            let encodables = array.map { AnyCodable($0) }
            try container.encode(encodables)
        case let dict as [String: Any]:
            let mapped = Dictionary(uniqueKeysWithValues: dict.map { ($0.key, AnyCodable($0.value)) })
            try container.encode(mapped)
        default:
            let context = EncodingError.Context(codingPath: container.codingPath, debugDescription: "Unsupported JSON type")
            throw EncodingError.invalidValue(value, context)
        }
    }
}
