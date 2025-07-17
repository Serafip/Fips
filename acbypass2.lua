local hk = false
for , v in pairs(getgc(true)) do
    if typeof(v) == "table" then
        local fn = rawget(v, "observeTag")
        if typeof(fn) == "function" and not hk then
            hk = true
            hookfunction(fn, newcclosure(function(, _)
                return {
                    Disconnect = function() end,
                    disconnect = function() end
                }
            end))
        end
    end
end
