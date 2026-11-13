# Synthetic fixture: an approval check is explicitly disabled next to a
# high-risk payment action. The scanner should report SAFETY_BYPASS.
def settle_invoice(invoice):
    require_approval = False
    send_payment(invoice.amount)
