using System.Collections.Concurrent;
using Ecommerce.Core.Domain;

namespace Ecommerce.Core.Engine;

public interface ICommerceEngine
{
    IReadOnlyList<Product> SearchProducts(string? query, string? category, decimal? maxPrice);
    Product? GetProduct(string productId);
    decimal GetWalletBalance(string userId);
    IReadOnlyList<LedgerEntry> GetLedgerEntries(string? accountId = null);
    OperationResult<Order> PlaceOrder(string authenticatedUserId, string targetUserId, string productId, int quantity, string idempotencyKey);
    Order? GetOrder(string orderId);
    IReadOnlyList<Order> GetUserOrders(string userId);
}

public sealed class CommerceEngine : ICommerceEngine
{
    private readonly ConcurrentDictionary<string, Product> _products = new();
    private readonly ConcurrentDictionary<string, Order> _orders = new();
    private readonly ConcurrentDictionary<string, Order> _idempotencyStore = new();
    private readonly List<LedgerEntry> _ledger = new();
    private readonly object _transactionLock = new();

    private const string PlatformEscrowAccount = "ACC_PLATFORM_REVENUE";

    public CommerceEngine()
    {
        SeedInitialData();
    }

    private void SeedInitialData()
    {
        var initialProducts = new[]
        {
            new Product("PRD-101", "LAP-PRO-M3", "MacBook Pro 16 M3 Max", "Electronics", 3499.00m, 8, "64GB Unified Memory, 2TB SSD, 16-core Neural Engine", 1),
            new Product("PRD-102", "KEY-MECH-K8", "Keychron K8 Pro Mechanical Keyboard", "Accessories", 119.00m, 25, "QMK/VIA Wireless, Gateron Brown Switch, Aluminum Frame", 1),
            new Product("PRD-103", "MON-DELL-4K", "Dell UltraSharp 32 4K USB-C Hub Monitor", "Monitors", 899.00m, 5, "IPS Black Technology, 90W Power Delivery, RJ45", 1),
            new Product("PRD-104", "HD-SONY-XM5", "Sony WH-1000XM5 Noise Canceling Headphones", "Audio", 398.00m, 15, "30-hour battery life, Multi-Noise Sensor technology", 1),
            new Product("PRD-105", "SRV-MINI-NUC", "ASUS NUC 14 Pro Mini Server", "Hardware", 750.00m, 4, "Intel Core Ultra 7, DDR5-5600 support, Dual 2.5G LAN", 1)
        };

        foreach (var p in initialProducts)
        {
            _products[p.Id] = p;
        }

        RecordDoubleEntry("TXN-GENESIS-01", "SYSTEM_TREASURY", "USR-AGENT-01", 10000.00m, "Initial Funding for USR-AGENT-01");
        RecordDoubleEntry("TXN-GENESIS-02", "SYSTEM_TREASURY", "USR-AUDIT-02", 500.00m, "Initial Funding for USR-AUDIT-02");
    }

    public IReadOnlyList<Product> SearchProducts(string? query, string? category, decimal? maxPrice)
    {
        var q = _products.Values.AsEnumerable();

        if (!string.IsNullOrWhiteSpace(query))
        {
            var term = query.Trim().ToLowerInvariant();
            q = q.Where(p => p.Name.ToLowerInvariant().Contains(term) ||
                             p.TechnicalSpecs.ToLowerInvariant().Contains(term) ||
                             p.Sku.ToLowerInvariant().Contains(term));
        }

        if (!string.IsNullOrWhiteSpace(category))
        {
            var cat = category.Trim().ToLowerInvariant();
            q = q.Where(p => p.Category.ToLowerInvariant() == cat);
        }

        if (maxPrice.HasValue)
        {
            q = q.Where(p => p.Price <= maxPrice.Value);
        }

        return q.OrderBy(p => p.Id).ToList();
    }

    public Product? GetProduct(string productId) =>
        _products.TryGetValue(productId, out var product) ? product : null;

    public decimal GetWalletBalance(string userId)
    {
        lock (_transactionLock)
        {
            return CalculateBalanceInternal(userId);
        }
    }

    private decimal CalculateBalanceInternal(string accountId)
    {
        return _ledger
            .Where(e => e.AccountId.Equals(accountId, StringComparison.OrdinalIgnoreCase))
            .Sum(e => e.Credit - e.Debit);
    }

    public IReadOnlyList<LedgerEntry> GetLedgerEntries(string? accountId = null)
    {
        lock (_transactionLock)
        {
            if (string.IsNullOrWhiteSpace(accountId))
                return _ledger.ToList();

            return _ledger
                .Where(e => e.AccountId.Equals(accountId, StringComparison.OrdinalIgnoreCase))
                .ToList();
        }
    }

    public OperationResult<Order> PlaceOrder(string authenticatedUserId, string targetUserId, string productId, int quantity, string idempotencyKey)
    {
        // 1. Data-Level Authorization: Prevent IDOR (Agent cannot buy on behalf of other users)
        if (!authenticatedUserId.Equals(targetUserId, StringComparison.OrdinalIgnoreCase))
        {
            return OperationResult<Order>.Failure("UNAUTHORIZED_DATA_ACCESS", 
                $"Security Violation: Authenticated user '{authenticatedUserId}' is not allowed to execute orders for target user '{targetUserId}'.");
        }

        if (string.IsNullOrWhiteSpace(idempotencyKey))
            return OperationResult<Order>.Failure("INVALID_IDEMPOTENCY_KEY", "IdempotencyKey is required for agentic transactions.");

        if (quantity <= 0)
            return OperationResult<Order>.Failure("INVALID_QUANTITY", "Quantity must be greater than zero.");

        lock (_transactionLock)
        {
            var compositeKey = $"{targetUserId}:{idempotencyKey}";
            if (_idempotencyStore.TryGetValue(compositeKey, out var existingOrder))
            {
                return OperationResult<Order>.Success(existingOrder);
            }

            if (!_products.TryGetValue(productId, out var product))
                return OperationResult<Order>.Failure("PRODUCT_NOT_FOUND", $"Product '{productId}' does not exist.");

            if (product.AvailableStock < quantity)
                return OperationResult<Order>.Failure("INSUFFICIENT_STOCK", $"Requested {quantity} units, but only {product.AvailableStock} available.");

            var totalAmount = product.Price * quantity;
            var currentBalance = CalculateBalanceInternal(targetUserId);
            if (currentBalance < totalAmount)
                return OperationResult<Order>.Failure("INSUFFICIENT_FUNDS", $"Wallet balance ({currentBalance:C}) is insufficient for total amount ({totalAmount:C}).");

            var updatedProduct = product with
            {
                AvailableStock = product.AvailableStock - quantity,
                Version = product.Version + 1
            };
            _products[productId] = updatedProduct;

            var txnId = $"TXN-{Guid.NewGuid().ToString("N")[..10].ToUpperInvariant()}";
            RecordDoubleEntry(txnId, targetUserId, PlatformEscrowAccount, totalAmount, $"Order purchase: {quantity}x {product.Sku}");

            var orderId = $"ORD-{Guid.NewGuid().ToString("N")[..8].ToUpperInvariant()}";
            var order = new Order(
                OrderId: orderId,
                UserId: targetUserId,
                IdempotencyKey: idempotencyKey,
                Items: new[] { new OrderItem(product.Id, product.Name, quantity, product.Price) },
                TotalAmount: totalAmount,
                Status: OrderStatus.Completed,
                CreatedAt: DateTimeOffset.UtcNow,
                LedgerTransactionId: txnId
            );

            _orders[orderId] = order;
            _idempotencyStore[compositeKey] = order;

            return OperationResult<Order>.Success(order);
        }
    }

    private void RecordDoubleEntry(string transactionId, string debitAccount, string creditAccount, decimal amount, string description)
    {
        var now = DateTimeOffset.UtcNow;
        _ledger.Add(new LedgerEntry($"LGE-{Guid.NewGuid().ToString("N")[..8]}", transactionId, debitAccount, amount, 0m, now, description));
        _ledger.Add(new LedgerEntry($"LGE-{Guid.NewGuid().ToString("N")[..8]}", transactionId, creditAccount, 0m, amount, now, description));
    }

    public Order? GetOrder(string orderId) =>
        _orders.TryGetValue(orderId, out var order) ? order : null;

    public IReadOnlyList<Order> GetUserOrders(string userId) =>
        _orders.Values.Where(o => o.UserId.Equals(userId, StringComparison.OrdinalIgnoreCase)).OrderByDescending(o => o.CreatedAt).ToList();
}