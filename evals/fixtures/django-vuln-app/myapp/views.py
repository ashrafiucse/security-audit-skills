# Fixture: intentionally insecure views.
from django.http import HttpResponse
from django.utils.safestring import mark_safe
from .models import Invoice


def search(request):
    # SEC-05: raw SQL with f-string user input
    rows = Invoice.objects.raw(
        f"SELECT * FROM myapp_invoice WHERE note = '{request.GET.get('q')}'"
    )
    return HttpResponse(str(list(rows)))


def greet(request):
    # SEC-06: mark_safe on user-controlled data
    return HttpResponse(mark_safe(request.GET.get('name', '')))


def invoice(request, invoice_id):
    # SEC-07: IDOR — object fetched by pk with no ownership check
    return HttpResponse(Invoice.objects.get(pk=invoice_id).note)
