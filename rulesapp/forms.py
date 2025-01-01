from django import forms
from ipaddress import ip_address, AddressValueError

class RuleEntryForm(forms.Form):
    action = forms.ChoiceField(
        label='Action',
        choices=[('pass', 'Pass'), ('reject', 'Reject')],
    )
    source = forms.CharField(
        label='Source (comma-separated)',
        widget=forms.Textarea(attrs={'placeholder': 'Enter multiple sources separated by commas'}),
    )
    destination = forms.CharField(
        label='Destination (comma-separated)',
        widget=forms.Textarea(attrs={'placeholder': 'Enter multiple destinations separated by commas'}),
    )
    port = forms.CharField(
        label='Port (comma-separated)',
        widget=forms.Textarea(attrs={'placeholder': 'Enter multiple ports separated by commas'}),
    )
    protocol = forms.ChoiceField(
        label='Protocol',
        choices=[('TCP', 'TCP'), ('UDP', 'UDP'), ('ANY', 'Any')],
    )

    def clean_source(self):
        sources = self.cleaned_data['source'].split(',')
        for src in sources:
            src = src.strip()
            try:
                ip_address(src)
            except AddressValueError:
                raise forms.ValidationError(f"Invalid IP address: {src}")
        return [src.strip() for src in sources]

    def clean_destination(self):
        destinations = self.cleaned_data['destination'].split(',')
        for dst in destinations:
            dst = dst.strip()
            try:
                ip_address(dst)
            except AddressValueError:
                raise forms.ValidationError(f"Invalid IP address: {dst}")
        return [dst.strip() for dst in destinations]

    def clean_port(self):
        ports = self.cleaned_data['port'].split(',')
        for port in ports:
            port = port.strip()
            if not port.isdigit() or not (1 <= int(port) <= 65535):
                raise forms.ValidationError(f"Invalid port: {port}")
        return [port.strip() for port in ports]

