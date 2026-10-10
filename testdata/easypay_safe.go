package payment

import (
	"context"
	"crypto/hmac"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
)

type SafeEasyPay struct {
	config map[string]string
	repo   *OrderRepository
}

type StoredOrder struct {
	OutTradeNo string
	Amount     string
	Status     string
}

type OrderRepository struct{}

func (r *OrderRepository) FindOrder(_ context.Context, _ string) (*StoredOrder, error) {
	return &StoredOrder{}, nil
}

func safeEasyPaySign(params map[string]string, pkey string) string {
	values := url.Values{}
	for key, value := range params {
		values.Set(key, value)
	}
	canonical := values.Encode()
	sum := md5.Sum([]byte(canonical + pkey))
	return hex.EncodeToString(sum[:])
}

func CanonicalizeReturnURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host != "site.example.com" || u.Path != "/payment/result" {
		return "", errors.New("invalid return url")
	}
	allowedQueryKeys := map[string]bool{"lang": true}
	query := u.Query()
	filtered := url.Values{}
	for key := range allowedQueryKeys {
		if value := query.Get(key); value != "" {
			filtered.Set(key, value)
		}
	}
	u.RawQuery = filtered.Encode()
	return u.String(), nil
}

func buildPaymentReturnURL(base string, orderID string, outTradeNo string, status string) string {
	u, _ := url.Parse(base)
	query := url.Values{}
	query.Set("order_id", orderID)
	query.Set("out_trade_no", outTradeNo)
	query.Set("status", status)
	u.RawQuery = query.Encode()
	return u.String()
}

func (e *SafeEasyPay) VerifyNotification(ctx context.Context, raw string, _ *http.Request) (*StoredOrder, error) {
	vals, err := url.ParseQuery(raw)
	if err != nil {
		return nil, err
	}
	params := map[string]string{}
	for key, values := range vals {
		if key != "sign" && len(values) > 0 {
			params[key] = values[0]
		}
	}
	expected := safeEasyPaySign(params, e.config["pkey"])
	if !hmac.Equal([]byte(expected), []byte(vals.Get("sign"))) {
		return nil, errors.New("invalid signature")
	}
	order, err := e.repo.FindOrder(ctx, vals.Get("out_trade_no"))
	if err != nil {
		return nil, err
	}
	if vals.Get("trade_status") != "TRADE_SUCCESS" || order.Amount != vals.Get("money") {
		return nil, errors.New("callback does not match order")
	}
	if order.Status != "pending" {
		return nil, errors.New("order already processed")
	}
	order.Status = "paid"
	return order, nil
}
