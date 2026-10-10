package payment

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

type EasyPay struct {
	config map[string]string
}

type Notification struct {
	OutTradeNo string
	Amount     string
	Status     string
}

func easyPaySign(params map[string]string, pkey string) string {
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var buf strings.Builder
	for _, k := range keys {
		buf.WriteString(k + "=" + params[k])
		buf.WriteString("&")
	}
	buf.WriteString(pkey)
	sum := md5.Sum([]byte(buf.String()))
	return hex.EncodeToString(sum[:])
}

func CanonicalizeReturnURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	if u.Scheme != "https" || u.Host != "site.example.com" {
		return "", errors.New("invalid return url")
	}
	if !strings.HasPrefix(u.Path, "/payment/result") {
		return "", errors.New("invalid return path")
	}
	return u.String(), nil
}

func buildPaymentReturnURL(base string, orderID string, outTradeNo string, status string) string {
	u, _ := url.Parse(base)
	q := u.Query()
	q.Set("order_id", orderID)
	q.Set("out_trade_no", outTradeNo)
	q.Set("status", status)
	u.RawQuery = q.Encode()
	return u.String()
}

func (e *EasyPay) VerifyNotification(ctx context.Context, raw string, r *http.Request) (*Notification, error) {
	vals, err := url.ParseQuery(raw)
	if err != nil {
		return nil, err
	}
	n := &Notification{
		OutTradeNo: vals.Get("out_trade_no"),
		Amount:     vals.Get("money"),
		Status:     vals.Get("trade_status"),
	}
	if n.Status != "TRADE_SUCCESS" {
		return nil, errors.New("not success")
	}
	return n, nil
}
