if not game:IsLoaded() then
    print("nl")
    game.Loaded:Wait()
end

local GuiService = game:GetService("StarterGui")
local TeleService = game:GetService("TeleportService")
local Players = game:GetService("Players")
local CoreGui = game:GetService("CoreGui")
local localserverjobid = game.JobId

local scyllajobid = readfile("eba.txt")
function tptojobid(jobid)
    TeleService:TeleportToPlaceInstance(game.PlaceId,jobid,Players.LocalPlayer)
    if CoreGui.RobloxPromptGui.promptOverlay:WaitForChild("ErrorPrompt") then
       if CoreGui.RobloxPromptGui.promptOverlay.ErrorPrompt.MessageArea.ErrorFrame.ButtonArea:FindFirstChild("OkButton") then
           game:GetService("GuiService"):ClearError()
           GuiService:SetCore("SendNotification", {Title = "Information",Text = "Error, Invalid Job ID";})
           task.wait(5)
       else
           GuiService:SetCore("SendNotification", {Title = "Information",Text = "Successful, Joining Server";})  
       end
    end
end

function handlescylla()
    local WorldEvent = game.Workspace.zones.fishing:FindFirstChild("Forsaken Veil - Scylla")
    --if scyllajobid == localserverjobid then task.wait(10000) return end
    if not WorldEvent then 
        tptojobid(scyllajobid)
    else 
        print("alr")
        return
    end
end

while wait(5) do
    if scyllajobid == "e" then print("Error occured") return end
    print(scyllajobid)
    handlescylla()
end
