# Common decoders

The cross-device correlation rules in `rules/common/cross_device_correlation.xml`
correlate on the normalized `srcip` / `srcuser` fields.

- **Linux** and **appliance** decoders already populate `srcip` / `srcuser` natively.
- **Windows** events do not, by default. The optional
  `decoders/windows/windows_normalize.xml` bridges this by adding `srcip` / `srcuser`
  to failed logons (4625), so the Windows leg can participate in cross-platform
  correlation. It is additive and off by default — enable it only if you want Windows
  included in the `129xxx` correlation rules.

No decoders are required in this folder itself.
