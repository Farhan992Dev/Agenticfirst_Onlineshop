namespace Ecommerce.Core.Domain;

public sealed record Product(
    string Id,
    string Sku,
    string Name,
    string Category,
    decimal Price,
    int AvailableStock,
    string TechnicalSpecs,
    uint Version
);

public sealed record OrderItem(string ProductId, string ProductName, int Quantity, decimal UnitPrice);

public enum OrderStatus
{
    Completed,
    Cancelled,
    Failed
}

public sealed record Order(
    string OrderId,
    string UserId,
    string IdempotencyKey,
    IReadOnlyList<OrderItem> Items,
    decimal TotalAmount,
    OrderStatus Status,
    DateTimeOffset CreatedAt,
    string LedgerTransactionId
);

public sealed record LedgerEntry(
    string EntryId,
    string TransactionId,
    string AccountId,
    decimal Debit,
    decimal Credit,
    DateTimeOffset Timestamp,
    string Description
);

public sealed record OperationResult<T>(bool IsSuccess, T? Data, string? ErrorCode, string? ErrorMessage)
{
    public static OperationResult<T> Success(T data) => new(true, data, null, null);
    public static OperationResult<T> Failure(string code, string message) => new(false, default, code, message);
}