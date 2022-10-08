// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using IdentityModel;
using System;
using System.Linq;
using System.Security.Claims;
using System.Text.Json;
using System.Text.Json.Serialization;

#pragma warning disable 1591

namespace IdentityServer4.Stores.Serialization
{
    public class ClaimsPrincipalConverter : JsonConverter<ClaimsPrincipal>
    {
        public override ClaimsPrincipal Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            var source = JsonSerializer.Deserialize<ClaimsPrincipalLite>(ref reader, options);
            var claims = source?.Claims.Select(x => new Claim(x.Type, x.Value, x.ValueType ?? ClaimValueTypes.String)).ToArray();
            var id = new ClaimsIdentity(claims, source?.AuthenticationType, JwtClaimTypes.Name, JwtClaimTypes.Role);
            return new ClaimsPrincipal(id);
        }

        public override void Write(Utf8JsonWriter writer, ClaimsPrincipal value, JsonSerializerOptions options)
        {
            var claims = value.Claims.Select(
                x => new ClaimLite
                {
                    Type = x.Type,
                    Value = x.Value,
                    ValueType = x.ValueType == ClaimValueTypes.String ? null : x.ValueType
                }).ToArray();

            var target = new ClaimsPrincipalLite
            {
                AuthenticationType = value.Identity!.AuthenticationType!,
                Claims = claims
            };

            JsonSerializer.Serialize(writer, target, options);
        }
    }
}
