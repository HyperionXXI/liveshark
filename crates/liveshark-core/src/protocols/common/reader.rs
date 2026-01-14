pub(crate) fn optional_nonzero_u8(value: u8) -> Option<u8> {
    if value == 0 { None } else { Some(value) }
}

#[cfg(test)]
mod tests {
    use super::optional_nonzero_u8;

    #[test]
    fn optional_nonzero_u8_zero() {
        assert_eq!(optional_nonzero_u8(0), None);
    }

    #[test]
    fn optional_nonzero_u8_value() {
        assert_eq!(optional_nonzero_u8(12), Some(12));
    }
}
