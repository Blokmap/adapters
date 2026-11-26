//! `#[derive(ErrorType)]`
//!
//! - every variant gets its name in snake_case: `NotFound` → `"not_found"`
//! - `#[error_type = "..."]` overrides the value for a variant, or for a struct
//! - `#[error_type(transparent)]` on a single-field variant (or struct)
//!   delegates to the inner value's `ErrorType`

use heck::ToSnakeCase;
use proc_macro2::{Span, TokenStream};
use quote::quote;
use syn::spanned::Spanned;
use syn::{parse_macro_input, Attribute, Data, DeriveInput, Error, Expr, ExprLit, Fields, Lit, LitStr, Meta, Result};

#[proc_macro_derive(ErrorType, attributes(error_type))]
pub fn derive_error_type(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    expand(input).unwrap_or_else(Error::into_compile_error).into()
}

/// What a single `#[error_type ...]` attribute says.
enum Rule {
    /// No attribute: derive the name.
    Default,
    /// `#[error_type = "..."]`
    Rename(LitStr),
    /// `#[error_type(transparent)]`
    Transparent(Span),
}

fn parse_rule(attrs: &[Attribute]) -> Result<Rule> {
    let mut rule = Rule::Default;
    for attr in attrs.iter().filter(|a| a.path().is_ident("error_type")) {
        if !matches!(rule, Rule::Default) {
            return Err(Error::new(attr.span(), "duplicate `error_type` attribute"));
        }
        rule = match &attr.meta {
            Meta::NameValue(nv) => match &nv.value {
                Expr::Lit(ExprLit { lit: Lit::Str(s), .. }) => {
                    validate(s)?;
                    Rule::Rename(s.clone())
                }
                other => return Err(Error::new(other.span(), "expected a string literal: `#[error_type = \"...\"]`")),
            },
            Meta::List(list) => {
                let mut transparent = false;
                list.parse_nested_meta(|m| {
                    if m.path.is_ident("transparent") {
                        transparent = true;
                        Ok(())
                    } else {
                        Err(m.error("unknown option, expected `transparent`"))
                    }
                })?;
                if !transparent {
                    return Err(Error::new(list.span(), "expected `#[error_type(transparent)]`"));
                }
                Rule::Transparent(attr.span())
            }
            Meta::Path(p) => {
                return Err(Error::new(
                    p.span(),
                    "expected `#[error_type = \"...\"]` or `#[error_type(transparent)]`",
                ))
            }
        };
    }
    Ok(rule)
}

/// Keep overrides grouping-key friendly: non-empty, no whitespace.
fn validate(s: &LitStr) -> Result<()> {
    let v = s.value();
    if v.is_empty() || v.chars().any(char::is_whitespace) {
        return Err(Error::new(s.span(), "error type must be non-empty and contain no whitespace"));
    }
    Ok(())
}

/// The single field of a transparent variant/struct, as a binding pattern.
fn single_field(fields: &Fields, span: Span) -> Result<TokenStream> {
    match fields {
        Fields::Unnamed(f) if f.unnamed.len() == 1 => Ok(quote!((inner))),
        Fields::Named(f) if f.named.len() == 1 => {
            let name = f.named[0].ident.as_ref().unwrap();
            Ok(quote!({ #name: inner }))
        }
        _ => Err(Error::new(span, "`#[error_type(transparent)]` requires exactly one field")),
    }
}

fn expand(input: DeriveInput) -> Result<TokenStream> {
    let name = &input.ident;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();
    let container_rule = parse_rule(&input.attrs)?;

    let body = match &input.data {
        Data::Enum(data) => {
            if !matches!(container_rule, Rule::Default) {
                return Err(Error::new(
                    name.span(),
                    "on enums, put `error_type` attributes on the variants",
                ));
            }
            if data.variants.is_empty() {
                quote!(match *self {})
            } else {
                let arms = data
                    .variants
                    .iter()
                    .map(|v| {
                        let ident = &v.ident;
                        Ok(match parse_rule(&v.attrs)? {
                            Rule::Transparent(span) => {
                                let pat = single_field(&v.fields, span)?;
                                quote!(Self::#ident #pat => ::error_type::ErrorType::error_type(inner))
                            }
                            Rule::Rename(s) => quote!(Self::#ident { .. } => #s),
                            Rule::Default => {
                                let s = LitStr::new(&ident.to_string().to_snake_case(), ident.span());
                                quote!(Self::#ident { .. } => #s)
                            }
                        })
                    })
                    .collect::<Result<Vec<_>>>()?;
                quote!(match self { #(#arms,)* })
            }
        }
        Data::Struct(data) => match container_rule {
            Rule::Transparent(span) => {
                let pat = single_field(&data.fields, span)?;
                quote!({
                    let Self #pat = self;
                    ::error_type::ErrorType::error_type(inner)
                })
            }
            Rule::Rename(s) => quote!(#s),
            Rule::Default => {
                let s = LitStr::new(&name.to_string().to_snake_case(), name.span());
                quote!(#s)
            }
        },
        Data::Union(_) => return Err(Error::new(name.span(), "`ErrorType` cannot be derived for unions")),
    };

    Ok(quote! {
        #[automatically_derived]
        impl #impl_generics ::error_type::ErrorType for #name #ty_generics #where_clause {
            fn error_type(&self) -> &'static str {
                #body
            }
        }
    })
}
